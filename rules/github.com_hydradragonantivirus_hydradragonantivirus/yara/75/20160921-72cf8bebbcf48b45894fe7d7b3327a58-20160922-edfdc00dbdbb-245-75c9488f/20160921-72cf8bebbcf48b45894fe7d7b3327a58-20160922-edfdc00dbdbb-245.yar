rule _20160921_72cf8bebbcf48b45894fe7d7b3327a58_20160922_edfdc00dbdbb_245 {
  meta:
    description = "datamaliciousorder - from files 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash2       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1  = "0(){return \"ZFe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";}" ascii
    $s2  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return" ascii
    $s3  = "rn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(fu" ascii
    $s4  = "){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s5  = "00(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";" ascii
    $s6  = "tion f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return " ascii
    $s7  = "ction f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s8  = "){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTi\";}" ascii
    $s9  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"EZu\";})(),(fu" ascii
    $s10 = "KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(functio" ascii
    $s11 = "00(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn" ascii
    $s12 = "000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\"" ascii
    $s13 = "turn \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s14 = ")(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(" ascii
    $s15 = "n \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s16 = "f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s17 = " \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(func" ascii
    $s18 = " f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu" ascii
    $s19 = "0(){return \"Do\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s20 = "n f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}