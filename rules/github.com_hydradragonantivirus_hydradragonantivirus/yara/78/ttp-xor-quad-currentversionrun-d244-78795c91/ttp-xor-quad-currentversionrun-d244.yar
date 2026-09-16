rule TTP_XOR_QUAD_CurrentVersionRun_d244 {
  strings:
    $key_d244 = { 81 2b [2] a5 25 [2] 8e 09 [2] a0 2b [2] b4 30 [2] bb 2a [2] a5 37 [2] a7 36 [2] bc 30 [2] a0 37 [2] bc 18 }

  condition:
    any of them
}