rule TTP_XOR_QUAD_CurrentVersionRun_d264 {
  strings:
    $key_d264 = { 81 0b [2] a5 05 [2] 8e 29 [2] a0 0b [2] b4 10 [2] bb 0a [2] a5 17 [2] a7 16 [2] bc 10 [2] a0 17 [2] bc 38 }

  condition:
    any of them
}