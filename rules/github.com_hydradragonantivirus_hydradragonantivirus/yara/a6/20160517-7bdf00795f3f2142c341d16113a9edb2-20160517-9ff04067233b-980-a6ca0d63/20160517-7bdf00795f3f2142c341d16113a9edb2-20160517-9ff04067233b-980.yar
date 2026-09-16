rule _20160517_7bdf00795f3f2142c341d16113a9edb2_20160517_9ff04067233b_980 {
  meta:
    description = "datamaliciousorder - from files 20160517_7bdf00795f3f2142c341d16113a9edb2.js, 20160517_9ff04067233bdd5c4d2edb2dd17fbda3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57ce9b99aef32422f8a9a5d13164f1e7b565f543ec23268d902b1cdb5e777617"
    hash2       = "d1ef21f700c5729144d3ab5c75a5e8cb9bf1ffc2c50ea2ced1ff495e1461012a"

  strings:
    $s1 = "function Scott /* tR  */(accinp0 /* tR  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* tR  */ = (123, Turkey); return devel0 /* tR  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* tR  */, Currency, (true, false));" fullword ascii
    $s4 = "place = /* tR  */(/* tR  */\"noitisop\").split(''/* tR  */).reverse(/* tR  */).join('');" fullword ascii
    $s5 = "function Scott /* tR  */(accinp0 /* tR  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 " ascii
    $s6 = "DENMARK1 /* tR  */= true;/* tR  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}