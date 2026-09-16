rule MAL_SystemBC_Lin_strings {
  meta:
    description   = "Matches strings found in SystemBC malware Linux samples."
    last_modified = "2024-03-01"
    author        = "@petermstewart"
    DaysofYara    = "61/100"
    sha256        = "cf831d33e7ccbbdc4ec5efca43e28c6a6a274348bb7bac5adcfee6e448a512d9"
    sha256        = "b68bfd96f2690058414aaeb7d418f376afe5ba65d18ee4441398807b06d520fd"

  strings:
    $a1 = "Rc4_crypt" fullword
    $a2 = "newConnection" fullword
    $a3 = "/tmp/socks5.sh" fullword
    $a4 = "cat <(echo '@reboot echo" fullword
    $a5 = "socks5_backconnect" fullword

  condition:
    uint32(0) == 0x464c457f and
    2 of them
}