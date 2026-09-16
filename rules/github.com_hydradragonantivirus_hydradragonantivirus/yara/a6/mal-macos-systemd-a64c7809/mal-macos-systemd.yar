rule mal_macos_systemd {
  meta:
    description = "Identify the macOS systemd (Demsty, ReverseWindow) backdoor."
    author      = "@shellcromancer"
    version     = "0.1"
    date        = "2023.02.28"
    reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.systemd"
    sample      = "6b379289033c4a17a0233e874003a843cd3c812403378af68ad4c16fe0d9b9c4"
    DaysofYARA  = "59/100"

  strings:
    $s1 = "This file is corrupted and connot be opened\n"
    $s2 = "#!/bin/sh\n. /etc/rc.common\nStartService (){\n    ConsoleMessage \"Start system Service\"\n"
    $s3 = "}\nStopService (){\n    return 0\n}\nRestartService (){\n    return 0\n}\nRunService \"$1\"\n"
    $s4 = "StartupParameters.plist"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of them
}