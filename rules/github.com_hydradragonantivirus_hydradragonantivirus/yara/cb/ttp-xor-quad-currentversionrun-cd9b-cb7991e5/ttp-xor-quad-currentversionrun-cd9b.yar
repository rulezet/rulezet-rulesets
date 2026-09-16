rule TTP_XOR_QUAD_CurrentVersionRun_cd9b {
  strings:
    $key_cd9b = { 9e f4 [2] ba fa [2] 91 d6 [2] bf f4 [2] ab ef [2] a4 f5 [2] ba e8 [2] b8 e9 [2] a3 ef [2] bf e8 [2] a3 c7 }

  condition:
    any of them
}