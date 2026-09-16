rule _20160921_98f234a378a6dd4e51c1730a4a700647_20160921_9aa040f4b657_55 {
  meta:
    description = "datamaliciousorder - from files 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash2       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"

  strings:
    $s1  = "Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(functio" ascii
    $s2  = "n \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYs\";})(),(fu" ascii
    $s3  = "unction f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Qj\";})(),(function f000(){ret" ascii
    $s4  = "ion f000(){return \"DYs\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return" ascii
    $s5  = "rn \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s6  = "return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})" ascii
    $s7  = "){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";}" ascii
    $s8  = "00(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\"" ascii
    $s9  = "eturn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})()" ascii
    $s10 = " \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s11 = "KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s12 = "eturn \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})()" ascii
    $s13 = "(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s14 = "\"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s15 = "(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s16 = ",(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){r" ascii
    $s17 = "\"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s18 = "nction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s19 = "unction f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s20 = "ction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}