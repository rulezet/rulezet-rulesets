rule _20160921_b15ce64784b080eff109e1bd1b00ebf6_20160922_99c635a67f89_868 {
  meta:
    description = "datamaliciousorder - from files 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1  = "\"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"UEg\";})(),(func" ascii
    $s2  = " f000(){return \"PTi\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s3  = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return " ascii
    $s4  = "),(function f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000()" ascii
    $s5  = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Uo" ascii
    $s6  = "Ij\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function " ascii
    $s7  = "eturn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(" ascii
    $s8  = "rn \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s9  = "00(){return \"PTi\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um\"" ascii
    $s10 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){ret" ascii
    $s11 = "\"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(func" ascii
    $s12 = "ion f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s13 = "n \"DAp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s14 = "GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(functi" ascii
    $s15 = " \"DNa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s16 = "0(){return \"Sv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";" ascii
    $s17 = "f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Do" ascii
    $s18 = "Tp\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s19 = "){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Do\";})" ascii
    $s20 = "(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DNa\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}