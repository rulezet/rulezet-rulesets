rule TTP_XOR_QUAD_CurrentVersionRun_d261 {
  strings:
    $key_d261 = { 81 0e [2] a5 00 [2] 8e 2c [2] a0 0e [2] b4 15 [2] bb 0f [2] a5 12 [2] a7 13 [2] bc 15 [2] a0 12 [2] bc 3d }

  condition:
    any of them
}