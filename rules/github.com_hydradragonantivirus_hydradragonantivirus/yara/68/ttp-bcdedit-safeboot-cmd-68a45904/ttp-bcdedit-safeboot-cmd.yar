rule TTP_bcdedit_safeboot_cmd {
  meta:
    description   = "Matches bcdedit command used to configure reboot to safemode - can be used to bypass security tools."
    last_modified = "2024-03-15"
    author        = "@petermstewart"
    DaysofYara    = "75/100"

  strings:
    $a = "bcdedit /set {default} safeboot" ascii wide nocase
    $b = "bcdedit.exe /set {default} safeboot" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and
    any of them
}