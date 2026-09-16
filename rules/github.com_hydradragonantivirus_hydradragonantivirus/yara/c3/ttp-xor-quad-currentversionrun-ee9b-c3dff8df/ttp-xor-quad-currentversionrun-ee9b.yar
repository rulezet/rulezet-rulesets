rule TTP_XOR_QUAD_CurrentVersionRun_ee9b {
  strings:
    $key_ee9b = { bd f4 [2] 99 fa [2] b2 d6 [2] 9c f4 [2] 88 ef [2] 87 f5 [2] 99 e8 [2] 9b e9 [2] 80 ef [2] 9c e8 [2] 80 c7 }

  condition:
    any of them
}