rule _20160517_091b943a32701b549a9d4dc45ccfa284_20160517_4890d4034f8e_1234 {
  meta:
    description = "datamaliciousorder - from files 20160517_091b943a32701b549a9d4dc45ccfa284.js, 20160517_4890d4034f8e794d8ffbf133de0f4c55.js, 20160517_61de01d215c011417bdcf2c4cda7aaf5.js, 20160517_bfbee812870834f5dfb33cef3f841d91.js, 20160517_da3dc0c24ab587b706d938862fc94dcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdb079f10606b0f004cd9f95038f00da07ba4b21d9c07ff684713a4e0102d1a2"
    hash2       = "87ccc4c37e93530e3d2275c541d25006ddb225c89b28138fb9e0b96129f8fa4e"
    hash3       = "9a9a83e4b74cd9807295300a4bc150902b29f56dd26682c5fb915f3b83b7386d"
    hash4       = "de768ef0bae10108416baaeb862b48ddfdb3edd5934d53f1fc2df3cbad396bc7"
    hash5       = "b11e339271fcf07438bb84809a02cb1ba8e7b6a3ae530affb50b4ec74a0f07a0"

  strings:
    $s1 = "devel1[aaa](Turkey0 /* D  */, Currency, (true, false));" fullword ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* D  */ = (123, Turkey); return devel0 /* D  */;};" fullword ascii
    $s3 = "function Scott /* D  */(accinp0 /* D  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s4 = "function Scott /* D  */(accinp0 /* D  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s5 = "DENMARK1 /* D  */= true;/* D  */" fullword ascii
    $s6 = "place = /* D  */(/* D  */\"noitisop\").split(''/* D  */).reverse(/* D  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}