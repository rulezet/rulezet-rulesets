rule TTP_XOR_QUAD_CurrentVersionRun_d55b {
  strings:
    $key_d55b = { 86 34 [2] a2 3a [2] 89 16 [2] a7 34 [2] b3 2f [2] bc 35 [2] a2 28 [2] a0 29 [2] bb 2f [2] a7 28 [2] bb 07 }

  condition:
    any of them
}