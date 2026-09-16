rule TTP_XOR_QUAD_CurrentVersionRun_d207 {
  strings:
    $key_d207 = { 81 68 [2] a5 66 [2] 8e 4a [2] a0 68 [2] b4 73 [2] bb 69 [2] a5 74 [2] a7 75 [2] bc 73 [2] a0 74 [2] bc 5b }

  condition:
    any of them
}