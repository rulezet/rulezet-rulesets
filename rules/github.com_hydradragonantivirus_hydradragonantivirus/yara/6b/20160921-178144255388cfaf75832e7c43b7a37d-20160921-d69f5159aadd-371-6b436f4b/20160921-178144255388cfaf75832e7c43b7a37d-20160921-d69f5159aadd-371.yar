rule _20160921_178144255388cfaf75832e7c43b7a37d_20160921_d69f5159aadd_371 {
  meta:
    description = "datamaliciousorder - from files 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash2       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash3       = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"

  strings:
    $s1  = "){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";}" ascii
    $s2  = "00(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\"" ascii
    $s3  = "(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s4  = "(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){re" ascii
    $s5  = "f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj" ascii
    $s6  = "turn \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s7  = "{return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})" ascii
    $s8  = "urn \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s9  = "n \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s10 = "00(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\"" ascii
    $s11 = "){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";}" ascii
    $s12 = "{return \"Ot\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(" ascii
    $s13 = " \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s14 = "return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})()" ascii
    $s15 = " \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s16 = "n \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(fun" ascii
    $s17 = "tion f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s18 = "Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s19 = "Pt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s20 = "turn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}