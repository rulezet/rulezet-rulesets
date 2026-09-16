rule TTP_XOR_QUAD_CurrentVersionRun_cec3 {
  strings:
    $key_cec3 = { 9d ac [2] b9 a2 [2] 92 8e [2] bc ac [2] a8 b7 [2] a7 ad [2] b9 b0 [2] bb b1 [2] a0 b7 [2] bc b0 [2] a0 9f }

  condition:
    any of them
}