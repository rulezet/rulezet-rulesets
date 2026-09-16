rule TTP_XOR_QUAD_CurrentVersionRun_dd43 {
  strings:
    $key_dd43 = { 8e 2c [2] aa 22 [2] 81 0e [2] af 2c [2] bb 37 [2] b4 2d [2] aa 30 [2] a8 31 [2] b3 37 [2] af 30 [2] b3 1f }

  condition:
    any of them
}