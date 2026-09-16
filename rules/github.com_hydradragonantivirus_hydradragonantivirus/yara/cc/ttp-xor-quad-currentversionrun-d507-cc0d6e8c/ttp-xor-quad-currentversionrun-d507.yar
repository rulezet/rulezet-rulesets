rule TTP_XOR_QUAD_CurrentVersionRun_d507 {
  strings:
    $key_d507 = { 86 68 [2] a2 66 [2] 89 4a [2] a7 68 [2] b3 73 [2] bc 69 [2] a2 74 [2] a0 75 [2] bb 73 [2] a7 74 [2] bb 5b }

  condition:
    any of them
}