rule mal_macos_ventir_watchdog {
  meta:
    description = "Identify macOS Ventir backdoor's watchdog component - reweb."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.21"
    references  = "https://securelist.com/the-ventir-trojan-assemble-your-macos-spy/67267/"
    sample      = "14e763ed4e95bf13a5b5c4ce98edbe2bbbec0d776d66726dfe2dd8b1f3079cb1"
    DaysofYARA  = "81/100"

  strings:
    $s0 = "/Users/maakira/"
    $s1 = "killall -9 update"
    $s2 = "reweb"

    $fp = "/proc/self/exe"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    all of ($s*) and
    not $fp
}