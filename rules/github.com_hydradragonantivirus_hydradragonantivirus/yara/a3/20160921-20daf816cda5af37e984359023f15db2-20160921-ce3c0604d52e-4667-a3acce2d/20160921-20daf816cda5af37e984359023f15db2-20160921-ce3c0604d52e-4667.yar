rule _20160921_20daf816cda5af37e984359023f15db2_20160921_ce3c0604d52e_4667 {
  meta:
    description = "datamaliciousorder - from files 20160921_20daf816cda5af37e984359023f15db2.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a45ccf6470d4ee194ed220125c42c5ac5d7c4b8a46cce738c6d12e9cc0bafea8"
    hash2       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "ction fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s2 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){r" ascii
    $s3 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){ret" ascii
    $s4 = "Go\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s5 = "k(){return \"Yk\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}