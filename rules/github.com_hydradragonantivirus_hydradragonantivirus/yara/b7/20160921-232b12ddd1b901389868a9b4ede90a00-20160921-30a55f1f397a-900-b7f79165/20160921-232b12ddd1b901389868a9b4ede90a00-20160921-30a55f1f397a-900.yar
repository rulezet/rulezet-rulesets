rule _20160921_232b12ddd1b901389868a9b4ede90a00_20160921_30a55f1f397a_900 {
  meta:
    description = "datamaliciousorder - from files 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_d4b576a05afdcd9649d02e422feb16d3.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash2       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash3       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash4       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash5       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash6       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash7       = "221c028d5b96ed7d5655800598b47b367ee2d1927826d126b5808db32c9a01f2"
    hash8       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1  = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Xg\";})(),(f" ascii
    $s2  = "unction fuck(){return \"Wo0\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){ret" ascii
    $s3  = "k(){return \"Xw\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";" ascii
    $s4  = "on fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s5  = "(function fuck(){return \"Ai\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){ret" ascii
    $s6  = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(functio" ascii
    $s7  = "urn \"CCb\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s8  = "})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xw\";})(),(function fuc" ascii
    $s9  = "n fuck(){return \"ZWu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"" ascii
    $s10 = "Qt\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s11 = " \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s12 = "function fuck(){return \"Xw\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){ret" ascii
    $s13 = "\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"PDf\";})(),(function f" ascii
    $s14 = "ion fuck(){return \"GJx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s15 = "){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})()" ascii
    $s16 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s17 = "),(function fuck(){return \"To\";})(),(function fuck(){return \"VMi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){" ascii
    $s18 = "rn \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s19 = ")(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(" ascii
    $s20 = "){return \"Xw\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"XCr\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}