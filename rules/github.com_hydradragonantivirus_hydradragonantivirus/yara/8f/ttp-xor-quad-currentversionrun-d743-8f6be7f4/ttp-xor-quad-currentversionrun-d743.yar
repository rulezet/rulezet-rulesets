rule TTP_XOR_QUAD_CurrentVersionRun_d743 {
  strings:
    $key_d743 = { 84 2c [2] a0 22 [2] 8b 0e [2] a5 2c [2] b1 37 [2] be 2d [2] a0 30 [2] a2 31 [2] b9 37 [2] a5 30 [2] b9 1f }

  condition:
    any of them
}