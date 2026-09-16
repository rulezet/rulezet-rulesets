rule _20160921_b2419a000449b12cbd6aff3732baf55d_20160921_da8c18b9dd89_1518 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash2       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"

  strings:
    $s1  = "){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})" ascii
    $s2  = "urn \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Oh\";})(),(f" ascii
    $s3  = "urn \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OPz\";})(),(" ascii
    $s4  = "),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){" ascii
    $s5  = "turn \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(f" ascii
    $s6  = "(){return \"XHj\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";" ascii
    $s7  = "fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"KVh" ascii
    $s8  = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retu" ascii
    $s9  = ",(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){re" ascii
    $s10 = "ck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We" ascii
    $s11 = "urn \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})()," ascii
    $s12 = "(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";" ascii
    $s13 = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}