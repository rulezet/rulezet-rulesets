rule TTP_XOR_QUAD_CurrentVersionRun_d69b {
  strings:
    $key_d69b = { 85 f4 [2] a1 fa [2] 8a d6 [2] a4 f4 [2] b0 ef [2] bf f5 [2] a1 e8 [2] a3 e9 [2] b8 ef [2] a4 e8 [2] b8 c7 }

  condition:
    any of them
}