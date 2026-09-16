rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_9_2_Virus_Hooke_257 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_9_2.vir, Virus.Hooker_Trojan.GenericKD.72483755_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7302e964793f853740b92325b2308b5537a880881a4acd99e6cb5ffbddc300ae"
    hash2       = "3535a218ecd54ea4f16bf768fa4cb310b0e79f758d6b6d2bfb57a6cc91fed0ad"

  strings:
    $s1 = "  -h, --human-readable       with -l and/or -s, print human readable sizes" fullword ascii
    $s2 = "  -k, --kibibytes            default to 1024-byte blocks for disk usage" fullword ascii
    $s3 = "                               as sort key if --sort=time (newest first)" fullword ascii
    $s4 = "  -t                         sort by modification time, newest first" fullword ascii
    $s5 = "      --time=WORD            with -l, show time as WORD instead of default" fullword ascii
    $s6 = "      --time-style=STYLE     with -l, show times using style STYLE:" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}