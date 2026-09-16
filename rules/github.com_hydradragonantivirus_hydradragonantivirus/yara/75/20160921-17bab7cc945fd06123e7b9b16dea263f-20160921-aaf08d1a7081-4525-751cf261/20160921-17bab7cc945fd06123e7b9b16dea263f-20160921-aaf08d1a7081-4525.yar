rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160921_aaf08d1a7081_4525 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"
    hash3       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"
    hash4       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1 = "n\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s2 = "g\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DYs\";})(),(functio" ascii
    $s3 = "nction f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){ret" ascii
    $s4 = "){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})" ascii
    $s5 = "){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}