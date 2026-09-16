rule TTP_XOR_QUAD_CurrentVersionRun_d275 {
  strings:
    $key_d275 = { 81 1a [2] a5 14 [2] 8e 38 [2] a0 1a [2] b4 01 [2] bb 1b [2] a5 06 [2] a7 07 [2] bc 01 [2] a0 06 [2] bc 29 }

  condition:
    any of them
}