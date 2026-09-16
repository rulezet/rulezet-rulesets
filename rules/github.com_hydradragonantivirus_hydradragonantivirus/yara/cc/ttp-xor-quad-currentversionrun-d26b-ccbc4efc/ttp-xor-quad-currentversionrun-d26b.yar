rule TTP_XOR_QUAD_CurrentVersionRun_d26b {
  strings:
    $key_d26b = { 81 04 [2] a5 0a [2] 8e 26 [2] a0 04 [2] b4 1f [2] bb 05 [2] a5 18 [2] a7 19 [2] bc 1f [2] a0 18 [2] bc 37 }

  condition:
    any of them
}