rule TTP_XOR_QUAD_CurrentVersionRun_c143 {
  strings:
    $key_c143 = { 92 2c [2] b6 22 [2] 9d 0e [2] b3 2c [2] a7 37 [2] a8 2d [2] b6 30 [2] b4 31 [2] af 37 [2] b3 30 [2] af 1f }

  condition:
    any of them
}