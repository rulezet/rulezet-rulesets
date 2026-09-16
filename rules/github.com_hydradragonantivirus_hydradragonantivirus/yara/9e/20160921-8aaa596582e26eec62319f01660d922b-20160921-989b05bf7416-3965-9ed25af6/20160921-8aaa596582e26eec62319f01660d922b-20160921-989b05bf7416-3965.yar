rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_989b05bf7416_3965 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_aaf08d1a708106f9bd09a913767a56e1.js, 20160921_cdeac57ac549120611856c7af0c490f6.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash4       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash5       = "f9cc4d7e90450eb48dcdeb77c2c486f0893efd6ae609a5f1c7bdf6439f61bda7"
    hash6       = "53694193718c2cb2f90fada2d6a11f07ab2c3f8451a0f41ae580b87a142e212e"
    hash7       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash8       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"
    hash9       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "ion f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s2 = ")(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s3 = "),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(" ascii
    $s4 = "){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(" ascii
    $s5 = "turn \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s6 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"K" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}