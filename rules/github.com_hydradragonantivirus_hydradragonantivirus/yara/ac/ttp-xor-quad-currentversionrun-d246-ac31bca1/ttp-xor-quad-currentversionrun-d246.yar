rule TTP_XOR_QUAD_CurrentVersionRun_d246 {
  strings:
    $key_d246 = { 81 29 [2] a5 27 [2] 8e 0b [2] a0 29 [2] b4 32 [2] bb 28 [2] a5 35 [2] a7 34 [2] bc 32 [2] a0 35 [2] bc 1a }

  condition:
    any of them
}