rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_d6eab67b6b3c_1106 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash3       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1  = "return \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(" ascii
    $s2  = "0(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";" ascii
    $s3  = "){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";" ascii
    $s4  = "(){return \"RVb\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DNa\"" ascii
    $s5  = "nction f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DIa\";})(),(function f000(){retu" ascii
    $s6  = "rn \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"Qp\";})(),(fun" ascii
    $s7  = " \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})(),(func" ascii
    $s8  = ")(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f00" ascii
    $s9  = "n \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(funct" ascii
    $s10 = "eturn \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"PTi\";})()" ascii
    $s11 = "on f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"" ascii
    $s12 = "rn \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(" ascii
    $s13 = "n \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(fu" ascii
    $s14 = "ction f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return" ascii
    $s15 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})()," ascii
    $s16 = "00(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq" ascii
    $s17 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}