rule _20160517_19a5668badd1fd09e10fdc493c9a3fd8_20160517_208e58fae119_1064 {
  meta:
    description = "datamaliciousorder - from files 20160517_19a5668badd1fd09e10fdc493c9a3fd8.js, 20160517_208e58fae119e7c0ec905a4726ab6fca.js, 20160517_7e3f2a69848a4071e7a77927a5e2e8db.js, 20160517_7eec71a1d83148960721273237ac428a.js, 20160517_86a95f883931cc5870af45c4e8efa03d.js, 20160517_b0619cb49f071254d31603595923f822.js, 20160517_f4b3e011d78f13fb29a580520b78cb87.js, 20160517_f63c5dd12adb61ddd29aa8e5364fcfac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e384a9ec4404057b07c48a2998484ea3a6a796df0481a71678feaa4238040b16"
    hash2       = "cd1ef4a730cb41f52026d0dd5d5d9dd52300a5326118fda8a6a1a4564c873814"
    hash3       = "31cb2780ff6df14dcb345b1de1d1cd84b3525ceebb15ab5718df4e3bf19ff211"
    hash4       = "833aa04017173e86d2be45b7b5eb7558eb3b00c7e195b239f30f56d414013c11"
    hash5       = "8fa28e5ac6fe7de92673b036a1ac9ed5ebe62dcf3c89f7fc075a8cc5dba0f1e0"
    hash6       = "622373596d32870aff9a9ada0eb6c3099401c8a32e34a1fdf6c6856941baaf30"
    hash7       = "de27bd02d9644229ee785de3b40d0adc544dd04f32620dfdbf9b6664268246d6"
    hash8       = "76e225d974a90245beb9885cc8041e31252942a91cc67a0a64fe9ef2de97c53c"

  strings:
    $s1 = "var nConverts1 /* V  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* V  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* V  */;};" fullword ascii
    $s4 = "batch =/* V  */ \"R\" + \"esponseB\"/* V  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s5 = "enjoy1 /* V  */ /* V  */= true;/* V  */" fullword ascii
    $s6 = "could = /* V  */(/* V  */\"noitisop\").split(''/* V  */).reverse(/* V  */).join('');" fullword ascii
    $s7 = "var enjoy1 /* V  */ = false;" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}