rule _20160921_9dad243650b7872772e7037b467b5a2e_20160922_edfdc00dbdbb_1218 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash2       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1  = "\"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"NBs\";})(),(funct" ascii
    $s2  = "n \"MJq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(f" ascii
    $s3  = "})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f00" ascii
    $s4  = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000()" ascii
    $s5  = "{return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s6  = "tion f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return" ascii
    $s7  = "000(){return \"TKp\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg" ascii
    $s8  = "n \"ZGq\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(f" ascii
    $s9  = "turn \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s10 = "(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lo\";}" ascii
    $s11 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Sj\";})(),(function" ascii
    $s12 = "){return \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s13 = "ction f000(){return \"ZFe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){retu" ascii
    $s14 = "(function f000(){return \"EZu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){r" ascii
    $s15 = "return \"BMj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s16 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}