rule _20160921_3bce2f31e98c152d025886ed17309773_20160921_570295874dae_4995 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_570295874daef65ccf11d909395ae377.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_edb059fcf68869f74200cd1e68a29bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash2       = "a5b27b9fc0152c3186c53a02507be373440217ec70f24fc85249bdaebbeb5494"
    hash3       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash4       = "9851e93d2e92fdd3882a14c4f00aface7bdc1495b43f7a98040092131f600e38"

  strings:
    $s1 = "x\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function" ascii
    $s2 = "rn \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(" ascii
    $s3 = "n f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"G" ascii
    $s4 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Um\";})(),(function f" ascii
    $s5 = "ction f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}