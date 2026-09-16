rule _20160921_20daf816cda5af37e984359023f15db2_20160921_a2f8f3f44ef6_4665 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"

  strings:
    $s1 = "unction fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s2 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"CCb\";})(),(functi" ascii
    $s3 = ";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuc" ascii
    $s4 = "k(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\"" ascii
    $s5 = "d\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}