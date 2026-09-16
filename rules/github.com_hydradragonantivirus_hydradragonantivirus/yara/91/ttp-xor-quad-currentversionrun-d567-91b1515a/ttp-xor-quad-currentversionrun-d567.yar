rule TTP_XOR_QUAD_CurrentVersionRun_d567 {
  strings:
    $key_d567 = { 86 08 [2] a2 06 [2] 89 2a [2] a7 08 [2] b3 13 [2] bc 09 [2] a2 14 [2] a0 15 [2] bb 13 [2] a7 14 [2] bb 3b }

  condition:
    any of them
}