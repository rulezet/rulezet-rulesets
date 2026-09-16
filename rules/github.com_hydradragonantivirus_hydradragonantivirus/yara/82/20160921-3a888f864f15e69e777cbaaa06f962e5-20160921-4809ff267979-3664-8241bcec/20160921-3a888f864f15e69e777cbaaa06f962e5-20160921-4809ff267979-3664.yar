rule _20160921_3a888f864f15e69e777cbaaa06f962e5_20160921_4809ff267979_3664 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_4809ff2679793c2b9af03e18ec3702ef.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash2       = "2c2d464143196a0237396460d274213cf5b3de772f4205aee0525b67ca1bfd6c"
    hash3       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash4       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1 = "Go\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(functio" ascii
    $s2 = "{return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(" ascii
    $s3 = "unction fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s4 = "Ai\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s5 = "n \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(fun" ascii
    $s6 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}