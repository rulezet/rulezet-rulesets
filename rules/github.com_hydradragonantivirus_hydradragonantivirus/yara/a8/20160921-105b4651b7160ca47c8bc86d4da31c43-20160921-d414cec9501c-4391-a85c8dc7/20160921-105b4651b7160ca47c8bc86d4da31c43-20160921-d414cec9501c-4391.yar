rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_d414cec9501c_4391 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"BGe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){re" ascii
    $s3 = "),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii
    $s4 = "\"MBg\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(funct" ascii
    $s5 = "Pu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}