rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_68d4a1cff7c2_4190 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"

  strings:
    $s1 = "ction f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTi\";})(),(function f000(){retu" ascii
    $s2 = "unction f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){retu" ascii
    $s3 = "{return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s4 = "{return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(" ascii
    $s5 = "})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}