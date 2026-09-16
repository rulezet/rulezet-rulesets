rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_87f13d652177_3886 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"

  strings:
    $s1 = "0(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s2 = "0(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";}" ascii
    $s3 = " f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s4 = "ion f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s5 = "turn \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()," ascii
    $s6 = "n\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}