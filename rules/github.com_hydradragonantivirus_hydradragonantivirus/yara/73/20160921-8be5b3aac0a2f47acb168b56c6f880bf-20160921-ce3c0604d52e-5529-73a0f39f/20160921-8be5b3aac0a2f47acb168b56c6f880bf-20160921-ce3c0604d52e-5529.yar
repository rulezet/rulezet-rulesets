rule _20160921_8be5b3aac0a2f47acb168b56c6f880bf_20160921_ce3c0604d52e_5529 {
  meta:
    description = "datamaliciousorder - from files 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js, 20160921_d4e094c14df45f61de0e1163f51e03e6.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash2       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"
    hash3       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"
    hash4       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = "return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})()," ascii
    $s2 = "n fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IP" ascii
    $s3 = "\"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(func" ascii
    $s4 = "Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function " ascii
    $s5 = "uck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}