rule _20160921_033cb159a63153428b22d38108b692e4_20160921_b2c7637ff56c_4147 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash3       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = ")(),(function f000(){return \"Qa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s2 = " \"ZIi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(func" ascii
    $s3 = "n \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(fu" ascii
    $s4 = "eturn \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})()" ascii
    $s5 = "})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}