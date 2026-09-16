rule _20160517_1e2406d7426cf3e2bb5cd0d726b950b4_20160517_73c58829f5f0_1238 {
  meta:
    description = "datamaliciousorder - from files 20160517_1e2406d7426cf3e2bb5cd0d726b950b4.js, 20160517_73c58829f5f01348a0245f5e809396fa.js, 20160517_bcd74a182edaf663b15aaffce3637a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af8a97cbcd013789a2c4b27c062fa46abff9e3f27613a49ed012067a143583b5"
    hash2       = "d75e1c03d9fd8a7407b4c5d9cd73ef94e454c87ff255bf167acb1c43b6922139"
    hash3       = "674b2db573ece40e84e5a8975a4cc2d716106bcb9172db30d9b12b0dbe70c99e"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* w  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* w  */ = (123, Turkey); return devel0 /* w  */;};" fullword ascii
    $s3 = "function Scott /* w  */(accinp0 /* w  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "function Scott /* w  */(accinp0 /* w  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* w  */= true;/* w  */" fullword ascii
    $s6 = "place = /* w  */(/* w  */\"noitisop\").split(''/* w  */).reverse(/* w  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}