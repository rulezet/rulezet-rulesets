rule TTP_XOR_QUAD_CurrentVersionRun_d565 {
  strings:
    $key_d565 = { 86 0a [2] a2 04 [2] 89 28 [2] a7 0a [2] b3 11 [2] bc 0b [2] a2 16 [2] a0 17 [2] bb 11 [2] a7 16 [2] bb 39 }

  condition:
    any of them
}