rule TTP_XOR_QUAD_CurrentVersionRun_d273 {
  strings:
    $key_d273 = { 81 1c [2] a5 12 [2] 8e 3e [2] a0 1c [2] b4 07 [2] bb 1d [2] a5 00 [2] a7 01 [2] bc 07 [2] a0 00 [2] bc 2f }

  condition:
    any of them
}