rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_42353ce25753_3460 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"

  strings:
    $s1 = "turn \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s2 = "urn \"DRx\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Hs\";})(),(f" ascii
    $s3 = "urn \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s4 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s5 = ")(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuc" ascii
    $s6 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}