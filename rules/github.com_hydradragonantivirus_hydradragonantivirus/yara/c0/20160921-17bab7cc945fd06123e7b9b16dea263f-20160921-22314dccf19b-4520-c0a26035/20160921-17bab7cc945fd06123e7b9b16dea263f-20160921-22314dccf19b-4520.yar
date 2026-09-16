rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_22314dccf19b_4520 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash3       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash4       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "{return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s2 = "unction f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii
    $s3 = " \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s4 = "0(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\"" ascii
    $s5 = "),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}