import "pe"
rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_690_1_Virus_Hijack_Dro_196 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_690_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f66d530bd51f94845efff9dad86c854c56de3642622a8a998a0d3f2532cf07d4"
    hash2       = "78f8013da4c07962bf263015dce1cd5e5a26507dc5fd5958a01f36ce863bac5e"

  strings:
    $s1  = "C:\\Documents and Settings\\All Users\\Documents\\My Music\\Sample Music\\New Stories (Highway Blues).wma" fullword wide
    $s2  = "Document1 - Microsoft Word" fullword wide
    $s3  = "Undefined Error Code:  " fullword wide
    $s4  = "Access to this key is denied" fullword wide
    $s5  = "nonda jangi" fullword wide
    $s6  = "Can't Read Key" fullword wide
    $s7  = "This place is not enough for us !" fullword wide
    $s8  = "Layar Bilu Penri sisi" fullword wide
    $s9  = "Sate ya ku bantal ila" fullword wide
    $s10 = "Samba ku kelet kupasuk" fullword wide
    $s11 = "Madadi buen pang maneng" fullword wide
    $s12 = "Batomo kungamet mole" fullword wide
    $s13 = "Mara pio ngibar mesa" fullword wide
    $s14 = "Printer Cpl" fullword wide
    $s15 = "The Registry Database is corrupt!" fullword wide
    $s16 = "Bad Key Name" fullword wide
    $s17 = "There is more data than the buffer has been " fullword wide
    $s18 = "Incorrect Format:" fullword wide
    $s19 = "Sudah bolong baru kecewa" fullword wide
    $s20 = "Can't Open Key" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "8a997ff635fd53f4e1e43c8213000861" and (8 of them)
    ) or (all of them)
}