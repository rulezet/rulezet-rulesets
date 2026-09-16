rule _20160921_60c26fdfafa2666b92246aea46e32175_20160921_9d32b55f93b8_1591 {
  meta:
    description = "datamaliciousorder - from files 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash2       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash3       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"

  strings:
    $s1  = " f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Z" ascii
    $s2  = "ction f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s3  = "tion f000(){return \"TKp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s4  = "w\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s5  = " \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(funct" ascii
    $s6  = "\"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(func" ascii
    $s7  = "(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";" ascii
    $s8  = "0(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";" ascii
    $s9  = "0(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\"" ascii
    $s10 = "ction f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii
    $s11 = "function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){re" ascii
    $s12 = "tion f000(){return \"ZGq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}