rule _20160921_bd40742bedf80aa0091b1fafd0a7ba4b_20160921_f6f229e035b3_5662 {
  meta:
    description = "datamaliciousorder - from files 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"
    hash2       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){r" ascii
    $s2 = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s3 = "})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Xg\";})(),(function fuck(" ascii
    $s4 = "ck(){return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Xg\";}" ascii
    $s5 = "u\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}