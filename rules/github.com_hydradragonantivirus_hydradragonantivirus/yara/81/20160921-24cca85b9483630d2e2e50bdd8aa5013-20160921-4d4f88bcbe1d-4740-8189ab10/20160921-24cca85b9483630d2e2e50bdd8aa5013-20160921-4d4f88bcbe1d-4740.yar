rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_4d4f88bcbe1d_4740 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160922_edfdc00dbdbb7dfd43478925b51e4a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash4       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash5       = "8672bbf21d7f10931a3f6328634b8b4e6160470a85d97fb93d56cb5eedb10599"

  strings:
    $s1 = "eturn \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s2 = "Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s3 = " f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UE" ascii
    $s4 = "tion f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s5 = ",(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}