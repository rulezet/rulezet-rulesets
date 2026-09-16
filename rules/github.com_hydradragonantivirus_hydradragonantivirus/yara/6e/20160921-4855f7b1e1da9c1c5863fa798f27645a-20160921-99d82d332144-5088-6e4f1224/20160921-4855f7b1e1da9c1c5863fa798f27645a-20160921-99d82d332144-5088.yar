rule _20160921_4855f7b1e1da9c1c5863fa798f27645a_20160921_99d82d332144_5088 {
  meta:
    description = "datamaliciousorder - from files 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_99d82d33214407e421e255b85f02daae.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash2       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"
    hash3       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash4       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"

  strings:
    $s1 = " f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy" ascii
    $s2 = "(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";}" ascii
    $s3 = "(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){r" ascii
    $s4 = "\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f" ascii
    $s5 = "eturn \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}