rule _20160921_67612c4ac75c1d3511dd9358b66e9fc5_20160921_b2419a000449_3020 {
  meta:
    description = "datamaliciousorder - from files 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash2       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash3       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"

  strings:
    $s1 = "n \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(f" ascii
    $s2 = "rn \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(f" ascii
    $s3 = "{return \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s4 = "unction fuck(){return \"Oh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s5 = "{return \"Jg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})()" ascii
    $s6 = "k(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\"" ascii
    $s7 = "rn \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}