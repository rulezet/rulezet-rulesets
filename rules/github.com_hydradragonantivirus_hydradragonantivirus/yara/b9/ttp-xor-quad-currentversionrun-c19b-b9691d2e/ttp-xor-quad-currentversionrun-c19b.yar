rule TTP_XOR_QUAD_CurrentVersionRun_c19b {
  strings:
    $key_c19b = { 92 f4 [2] b6 fa [2] 9d d6 [2] b3 f4 [2] a7 ef [2] a8 f5 [2] b6 e8 [2] b4 e9 [2] af ef [2] b3 e8 [2] af c7 }

  condition:
    any of them
}