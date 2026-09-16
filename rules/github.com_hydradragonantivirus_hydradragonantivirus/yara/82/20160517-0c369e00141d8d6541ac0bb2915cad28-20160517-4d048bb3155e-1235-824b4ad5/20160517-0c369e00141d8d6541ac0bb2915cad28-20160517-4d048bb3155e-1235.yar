rule _20160517_0c369e00141d8d6541ac0bb2915cad28_20160517_4d048bb3155e_1235 {
  meta:
    description = "datamaliciousorder - from files 20160517_0c369e00141d8d6541ac0bb2915cad28.js, 20160517_4d048bb3155e45e45d34f19ecf2329ee.js, 20160517_b9745b5b893d36fb3709df4ce6f39c23.js, 20160517_f63d59f4efdfe179a5482eabdcb6a23f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9af9430b661b0564d4d7ffe167d54a1198d5884c8d75969d76751e4fe24a0fce"
    hash2       = "8786b4e6266192ef938a5378af24820c0e977c6a8f3a2347cd1a8dede3e2f759"
    hash3       = "8d00abd117158a845a2e62a49dcd7e7203a5f18efb6c05628de0a36d2e0052b7"
    hash4       = "b9cb273c73a159aec42a8c2ec9696e2252449a37b7ed82ee313aa52168f847bf"

  strings:
    $s1 = "function Scott /* S  */(accinp0 /* S  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* S  */ = (123, Turkey); return devel0 /* S  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* S  */, Currency, (true, false));" fullword ascii
    $s4 = "place = /* S  */(/* S  */\"noitisop\").split(''/* S  */).reverse(/* S  */).join('');" fullword ascii
    $s5 = "DENMARK1 /* S  */= true;/* S  */" fullword ascii
    $s6 = "function Scott /* S  */(accinp0 /* S  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}