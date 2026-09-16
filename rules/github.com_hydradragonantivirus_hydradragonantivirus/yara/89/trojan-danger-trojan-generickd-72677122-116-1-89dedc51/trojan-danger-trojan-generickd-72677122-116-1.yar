rule Trojan_Danger_Trojan_GenericKD_72677122_116_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_116_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0353c7c7f338f1e593356798eb341631339135d7fbeb61b5e57ff806cd6f18f4"

  strings:
    $s1  = "netsh dump" fullword ascii
    $s2  = "Mozilla/4.0 (compatible; MSIE6.0;Windows NT 5.1)" fullword ascii
    $s3  = " /c echo ========== >> " fullword ascii
    $s4  = "net group \"domain computers\" /domain" fullword ascii
    $s5  = "net user /domain" fullword ascii
    $s6  = "domain host" fullword ascii
    $s7  = " /c echo " fullword ascii
    $s8  = "domain user" fullword ascii
    $s9  = "domain computers" fullword ascii
    $s10 = "net group \"domain admins\" /domain" fullword ascii
    $s11 = "net view /domain" fullword ascii
    $s12 = "net group \"domain controllers\" /domain" fullword ascii
    $s13 = "Current User Startup" fullword ascii
    $s14 = "Current User Soft" fullword ascii
    $s15 = "net start" fullword ascii
    $s16 = "Machine User Startup" fullword ascii
    $s17 = "domain admins" fullword ascii
    $s18 = "net user" fullword ascii
    $s19 = "Machine Soft" fullword ascii
    $s20 = "net view" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}