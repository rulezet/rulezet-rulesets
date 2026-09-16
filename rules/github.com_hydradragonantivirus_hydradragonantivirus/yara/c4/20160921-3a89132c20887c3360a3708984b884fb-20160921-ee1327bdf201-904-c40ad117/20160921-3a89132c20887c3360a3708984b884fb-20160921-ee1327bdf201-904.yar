rule _20160921_3a89132c20887c3360a3708984b884fb_20160921_ee1327bdf201_904 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a89132c20887c3360a3708984b884fb.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"
    hash2       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1  = "eturn \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})()," ascii
    $s2  = "u\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3  = "return \"IAa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})()" ascii
    $s4  = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sv\";})" ascii
    $s5  = "f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"WI" ascii
    $s6  = "unction f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s7  = ",(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})(),(function f000(){r" ascii
    $s8  = ";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BMj\";})(),(function f00" ascii
    $s9  = "\"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s10 = "nction f000(){return \"Oh\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s11 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(" ascii
    $s12 = "ion f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s13 = "),(function f000(){return \"DNa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"TKp\";})(),(function f000(" ascii
    $s14 = "n f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return " ascii
    $s15 = "0(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg" ascii
    $s16 = "n f000(){return \"EZu\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s17 = "rn \"Vj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(fu" ascii
    $s18 = "on f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s19 = "urn \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DIa\";})(),(f" ascii
    $s20 = "urn \"DAp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}