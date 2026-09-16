rule _20160921_68d4a1cff7c2dbc758cf0077184d0d52_20160921_a65ac281dbfd_3869 {
  meta:
    description = "datamaliciousorder - from files 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash2       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash3       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz" ascii
    $s2 = "{return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yi\";})(" ascii
    $s3 = "on f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})()" ascii
    $s5 = ")(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii
    $s6 = "function f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}