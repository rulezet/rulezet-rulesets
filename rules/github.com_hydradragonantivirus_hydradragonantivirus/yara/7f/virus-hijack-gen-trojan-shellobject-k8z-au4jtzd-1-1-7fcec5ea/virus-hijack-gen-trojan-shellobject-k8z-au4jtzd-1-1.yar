rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_au4JtZd_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@au4JtZd_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17c184859f0ba6c44db4b486aeb091ad2dae5f6078816a9b03bc71ad78d97d41"

  strings:
    $s1  = "PGP PUBLIC KEY " fullword ascii
    $s2  = "ofatal error: cgo" fullword ascii
    $s3  = "byname" fullword ascii
    $s4  = "mass*@e" fullword ascii
    $s5  = "doPa%P(R" fullword ascii
    $s6  = "*ATOMICS" fullword ascii
    $s7  = " Go build ID: \"0J3q3ZC4hlrRyYBc" fullword ascii
    $s8  = "Even]X*@Ce" fullword ascii
    $s9  = "method:}D" fullword ascii
    $s10 = "name?Xj" fullword ascii
    $s11 = "sk4u\" error:" fullword ascii
    $s12 = "Scan)U" fullword ascii
    $s13 = "shift%" fullword ascii
    $s14 = "seed*P" fullword ascii
    $s15 = "used)2" fullword ascii
    $s16 = "Perm]+" fullword ascii
    $s17 = "w,chinG;" fullword ascii
    $s18 = "3Q`neon`" fullword ascii
    $s19 = ")zone%" fullword ascii
    $s20 = "}h]Math%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}