rule _20160921_68d4a1cff7c2dbc758cf0077184d0d52_20160921_9c9fcc818a70_3023 {
  meta:
    description = "datamaliciousorder - from files 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash2       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"

  strings:
    $s1 = ")(),(function f000(){return \"Br\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(),(function f000" ascii
    $s2 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";" ascii
    $s3 = "ction f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){retu" ascii
    $s4 = "nction f000(){return \"Tn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s5 = "s\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s6 = "urn \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(fu" ascii
    $s7 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}