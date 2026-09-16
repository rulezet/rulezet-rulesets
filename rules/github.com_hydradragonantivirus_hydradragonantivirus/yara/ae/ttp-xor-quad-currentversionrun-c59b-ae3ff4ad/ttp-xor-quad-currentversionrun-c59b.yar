rule TTP_XOR_QUAD_CurrentVersionRun_c59b {
  strings:
    $key_c59b = { 96 f4 [2] b2 fa [2] 99 d6 [2] b7 f4 [2] a3 ef [2] ac f5 [2] b2 e8 [2] b0 e9 [2] ab ef [2] b7 e8 [2] ab c7 }

  condition:
    any of them
}