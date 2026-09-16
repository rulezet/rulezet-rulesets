rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_9d32b55f93b8_3994 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js, 20160921_ec2541ade561a4750092fda52be6f269.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash3       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash4       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"
    hash5       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"
    hash6       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";" ascii
    $s2 = " f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"G" ascii
    $s3 = ",(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){r" ascii
    $s4 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function" ascii
    $s5 = "\"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(funct" ascii
    $s6 = "nction f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}