rule _20160921_02b826231ece268e91633311d2c70554_20160921_08977f7f9e06_4142 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_a2977e58d35241f07c3f294ca2097899.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash3       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash4       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash5       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash6       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"

  strings:
    $s1 = "(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){re" ascii
    $s2 = "tion f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s3 = "turn \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(" ascii
    $s4 = " f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt" ascii
    $s5 = "Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}