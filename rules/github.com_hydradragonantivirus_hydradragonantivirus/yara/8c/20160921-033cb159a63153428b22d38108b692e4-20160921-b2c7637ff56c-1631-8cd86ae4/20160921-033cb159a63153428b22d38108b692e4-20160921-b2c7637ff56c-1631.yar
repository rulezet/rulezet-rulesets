rule _20160921_033cb159a63153428b22d38108b692e4_20160921_b2c7637ff56c_1631 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash3       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1  = "00(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn" ascii
    $s2  = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f00" ascii
    $s3  = "return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(" ascii
    $s4  = " \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(func" ascii
    $s5  = "\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Wy\";})(),(function " ascii
    $s6  = "0(){return \"Go\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\"" ascii
    $s7  = "ion f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return" ascii
    $s8  = "f000(){return \"MDb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn" ascii
    $s9  = "unction f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii
    $s10 = "0(){return \"Vj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";}" ascii
    $s11 = " f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MM" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}