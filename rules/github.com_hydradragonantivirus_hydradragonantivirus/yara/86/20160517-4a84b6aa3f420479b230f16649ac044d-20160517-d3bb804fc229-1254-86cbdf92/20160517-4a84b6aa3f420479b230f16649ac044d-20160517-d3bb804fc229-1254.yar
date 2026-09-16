rule _20160517_4a84b6aa3f420479b230f16649ac044d_20160517_d3bb804fc229_1254 {
  meta:
    description = "datamaliciousorder - from files 20160517_4a84b6aa3f420479b230f16649ac044d.js, 20160517_d3bb804fc2291fce616ae3ca3d821c4f.js, 20160517_d7e9569e28502417f65f8c2ab7cc2f0e.js, 20160517_ff6f89cc296e0200fbee65584386013a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a059659f4e54c8d80581465071179565636ba50ba73d4109eb172e64e06b564"
    hash2       = "993116b9a9e661a0aaa1d9c80db65f6bbd1efb913f3835d9bd8d9b0094b93c4c"
    hash3       = "61eefb4dc239945ec6dde1f618efbe01e75572af336fbd0595a6e30ab1ffdb4a"
    hash4       = "27c9662467201eea36c3c252d4cc1e124d5165037fc249aaf8a88800ccd238e0"

  strings:
    $s1 = "function Scott /* Y  */(accinp0 /* Y  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "devel1[aaa](Turkey0 /* Y  */, Currency, (true, false));" fullword ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* Y  */ = (123, Turkey); return devel0 /* Y  */;};" fullword ascii
    $s4 = "place = /* Y  */(/* Y  */\"noitisop\").split(''/* Y  */).reverse(/* Y  */).join('');" fullword ascii
    $s5 = "function Scott /* Y  */(accinp0 /* Y  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "DENMARK1 /* Y  */= true;/* Y  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}