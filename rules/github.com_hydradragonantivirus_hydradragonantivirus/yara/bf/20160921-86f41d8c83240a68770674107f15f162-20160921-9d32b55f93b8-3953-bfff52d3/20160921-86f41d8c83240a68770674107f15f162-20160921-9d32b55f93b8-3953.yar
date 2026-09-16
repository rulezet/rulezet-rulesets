rule _20160921_86f41d8c83240a68770674107f15f162_20160921_9d32b55f93b8_3953 {
  meta:
    description = "datamaliciousorder - from files 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash2       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash3       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"

  strings:
    $s1 = "rn \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(fu" ascii
    $s2 = "n \"KDh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(fu" ascii
    $s3 = "n \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(fun" ascii
    $s4 = ")(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000" ascii
    $s5 = "000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj" ascii
    $s6 = "000(){return \"Sq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}