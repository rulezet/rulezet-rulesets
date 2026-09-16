rule _20160517_9035cf1cf5100f437b6554828d15f614_20160517_df82d8671bff_1265 {
  meta:
    description = "datamaliciousorder - from files 20160517_9035cf1cf5100f437b6554828d15f614.js, 20160517_df82d8671bfff1c52ae882c3d40071a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bbbe42bbd66e5bf9ed46cd629e27eb6b588099f6f63264516401924b830aecb"
    hash2       = "28592b2831044553507e4bff416643a43b26a65aff59ba0c7f49fbd44d744b56"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* s  */, Currency, (true, false));" fullword ascii
    $s2 = "function Scott /* s  */(accinp0 /* s  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "function DENMARK(Turkey) {var devel0 /* s  */ = (123, Turkey); return devel0 /* s  */;};" fullword ascii
    $s4 = "DENMARK1 /* s  */= true;/* s  */" fullword ascii
    $s5 = "place = /* s  */(/* s  */\"noitisop\").split(''/* s  */).reverse(/* s  */).join('');" fullword ascii
    $s6 = "function Scott /* s  */(accinp0 /* s  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}