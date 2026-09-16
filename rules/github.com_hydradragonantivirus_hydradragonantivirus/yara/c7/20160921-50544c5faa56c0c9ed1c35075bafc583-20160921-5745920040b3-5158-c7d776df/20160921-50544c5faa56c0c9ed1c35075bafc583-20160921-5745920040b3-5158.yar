rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_5745920040b3_5158 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash3       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"
    hash4       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"

  strings:
    $s1 = "uck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu" ascii
    $s2 = ",(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){r" ascii
    $s3 = "{return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jg\";})()" ascii
    $s4 = "on fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"F" ascii
    $s5 = "Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}