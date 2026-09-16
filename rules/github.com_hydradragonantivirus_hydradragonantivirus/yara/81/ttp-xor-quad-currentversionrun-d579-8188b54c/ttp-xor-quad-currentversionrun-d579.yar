rule TTP_XOR_QUAD_CurrentVersionRun_d579 {
  strings:
    $key_d579 = { 86 16 [2] a2 18 [2] 89 34 [2] a7 16 [2] b3 0d [2] bc 17 [2] a2 0a [2] a0 0b [2] bb 0d [2] a7 0a [2] bb 25 }

  condition:
    any of them
}