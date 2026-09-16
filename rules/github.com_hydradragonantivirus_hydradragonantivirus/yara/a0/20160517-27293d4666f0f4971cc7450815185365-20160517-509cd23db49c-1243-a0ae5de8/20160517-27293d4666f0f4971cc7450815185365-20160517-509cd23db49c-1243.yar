rule _20160517_27293d4666f0f4971cc7450815185365_20160517_509cd23db49c_1243 {
  meta:
    description = "datamaliciousorder - from files 20160517_27293d4666f0f4971cc7450815185365.js, 20160517_509cd23db49cb7c838d7452f49f13553.js, 20160517_d3fdc8d54d2df94bac5a8818daf0b825.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e731ae46df17d165b9d039b96031876e9b977e712eab15bba21c748fd52e0d5c"
    hash2       = "5f8d9a702e768bcab477de577c513c09299a8624575c2c9518703ea1c1c42001"
    hash3       = "05bcc78ce0f46f8dc5f36b8a412b6e9d20a3ddfab7ba24933b76326f3762f9de"

  strings:
    $s1 = "function DENMARK(Turkey) {var devel0 /* z  */ = (123, Turkey); return devel0 /* z  */;};" fullword ascii
    $s2 = "function Scott /* z  */(accinp0 /* z  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s3 = "devel1[aaa](Turkey0 /* z  */, Currency, (true, false));" fullword ascii
    $s4 = "DENMARK1 /* z  */= true;/* z  */" fullword ascii
    $s5 = "place = /* z  */(/* z  */\"noitisop\").split(''/* z  */).reverse(/* z  */).join('');" fullword ascii
    $s6 = "function Scott /* z  */(accinp0 /* z  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}