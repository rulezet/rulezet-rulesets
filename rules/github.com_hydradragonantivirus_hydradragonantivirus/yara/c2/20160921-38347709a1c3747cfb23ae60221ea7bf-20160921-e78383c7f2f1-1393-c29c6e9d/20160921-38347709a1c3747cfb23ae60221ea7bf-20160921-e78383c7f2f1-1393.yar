rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_e78383c7f2f1_1393 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1  = " fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"E" ascii
    $s2  = "function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s3  = "eturn \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4  = "nction fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return" ascii
    $s5  = "ck(){return \"ZWu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\"" ascii
    $s6  = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s7  = "function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){r" ascii
    $s8  = "\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function f" ascii
    $s9  = "eturn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})()," ascii
    $s10 = "})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"OPz\";})(),(function fu" ascii
    $s11 = "\"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s12 = "nction fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){retur" ascii
    $s13 = "return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"KVh\";})(" ascii
    $s14 = "\"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}