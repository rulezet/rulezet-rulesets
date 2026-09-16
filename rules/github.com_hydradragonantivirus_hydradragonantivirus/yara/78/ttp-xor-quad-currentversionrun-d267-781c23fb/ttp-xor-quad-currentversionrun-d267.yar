rule TTP_XOR_QUAD_CurrentVersionRun_d267 {
  strings:
    $key_d267 = { 81 08 [2] a5 06 [2] 8e 2a [2] a0 08 [2] b4 13 [2] bb 09 [2] a5 14 [2] a7 15 [2] bc 13 [2] a0 14 [2] bc 3b }

  condition:
    any of them
}