rule _20160921_6bf1e6b71f68264911cd95f601a6cc98_20160921_7b23bcfdd128_3029 {
  meta:
    description = "datamaliciousorder - from files 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash2       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"

  strings:
    $s1 = "ion fuck(){return \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s2 = "k(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";" ascii
    $s3 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s4 = "{return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})" ascii
    $s5 = "c\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function" ascii
    $s6 = "nction fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retu" ascii
    $s7 = "function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}