rule TTP_XOR_QUAD_CurrentVersionRun_d258 {
  strings:
    $key_d258 = { 81 37 [2] a5 39 [2] 8e 15 [2] a0 37 [2] b4 2c [2] bb 36 [2] a5 2b [2] a7 2a [2] bc 2c [2] a0 2b [2] bc 04 }

  condition:
    any of them
}