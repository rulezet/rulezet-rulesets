rule TTP_XOR_QUAD_CurrentVersionRun_d277 {
  strings:
    $key_d277 = { 81 18 [2] a5 16 [2] 8e 3a [2] a0 18 [2] b4 03 [2] bb 19 [2] a5 04 [2] a7 05 [2] bc 03 [2] a0 04 [2] bc 2b }

  condition:
    any of them
}