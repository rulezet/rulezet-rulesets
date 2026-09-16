rule TTP_XOR_QUAD_CurrentVersionRun_c743 {
  strings:
    $key_c743 = { 94 2c [2] b0 22 [2] 9b 0e [2] b5 2c [2] a1 37 [2] ae 2d [2] b0 30 [2] b2 31 [2] a9 37 [2] b5 30 [2] a9 1f }

  condition:
    any of them
}