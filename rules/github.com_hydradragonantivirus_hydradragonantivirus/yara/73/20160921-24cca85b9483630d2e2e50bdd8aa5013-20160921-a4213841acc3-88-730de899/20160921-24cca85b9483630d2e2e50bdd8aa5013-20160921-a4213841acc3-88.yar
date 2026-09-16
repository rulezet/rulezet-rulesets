rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_a4213841acc3_88 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"

  strings:
    $s1  = "){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";" ascii
    $s2  = "ction f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MJq\";})(),(function f000(){retur" ascii
    $s3  = "n f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"M" ascii
    $s4  = "o\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5  = "\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f" ascii
    $s6  = "){return \"ZIi\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";}" ascii
    $s7  = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(funct" ascii
    $s8  = "f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp" ascii
    $s9  = "00(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc" ascii
    $s10 = "n \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s11 = "eturn \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})()" ascii
    $s12 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(" ascii
    $s13 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";}" ascii
    $s14 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f00" ascii
    $s15 = "(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s16 = "tion f000(){return \"ZFe\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s17 = " \"IAa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s18 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s19 = "(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lo\";})(),(function f000(){" ascii
    $s20 = "f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}