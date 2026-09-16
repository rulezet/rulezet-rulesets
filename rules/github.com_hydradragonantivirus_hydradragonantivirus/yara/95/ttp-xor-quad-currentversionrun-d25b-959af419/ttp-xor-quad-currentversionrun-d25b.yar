rule TTP_XOR_QUAD_CurrentVersionRun_d25b {
  strings:
    $key_d25b = { 81 34 [2] a5 3a [2] 8e 16 [2] a0 34 [2] b4 2f [2] bb 35 [2] a5 28 [2] a7 29 [2] bc 2f [2] a0 28 [2] bc 07 }

  condition:
    any of them
}