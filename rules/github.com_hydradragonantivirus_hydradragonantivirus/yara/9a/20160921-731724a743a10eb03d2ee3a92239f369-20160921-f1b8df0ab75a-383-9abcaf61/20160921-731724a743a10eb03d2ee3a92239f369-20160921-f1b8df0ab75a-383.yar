rule _20160921_731724a743a10eb03d2ee3a92239f369_20160921_f1b8df0ab75a_383 {
  meta:
    description = "datamaliciousorder - from files 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash2       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1  = "on f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii
    $s2  = "turn \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s3  = "n \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(func" ascii
    $s4  = "00(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s5  = "0(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";}" ascii
    $s6  = " f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi" ascii
    $s7  = "function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s8  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s9  = "function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s10 = "Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s11 = "unction f000(){return \"Um\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){retu" ascii
    $s12 = "{return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})()," ascii
    $s13 = "urn \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(fu" ascii
    $s14 = "urn \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(fu" ascii
    $s15 = "000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc" ascii
    $s16 = "ction f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s17 = "(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){re" ascii
    $s18 = "turn \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s19 = " \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s20 = "tion f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}