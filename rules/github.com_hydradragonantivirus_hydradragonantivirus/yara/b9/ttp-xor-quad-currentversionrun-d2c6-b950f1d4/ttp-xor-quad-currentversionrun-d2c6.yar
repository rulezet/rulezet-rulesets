rule TTP_XOR_QUAD_CurrentVersionRun_d2c6 {
  strings:
    $key_d2c6 = { 81 a9 [2] a5 a7 [2] 8e 8b [2] a0 a9 [2] b4 b2 [2] bb a8 [2] a5 b5 [2] a7 b4 [2] bc b2 [2] a0 b5 [2] bc 9a }

  condition:
    any of them
}