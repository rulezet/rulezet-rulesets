rule TTP_XOR_QUAD_CurrentVersionRun_d5c7 {
  strings:
    $key_d5c7 = { 86 a8 [2] a2 a6 [2] 89 8a [2] a7 a8 [2] b3 b3 [2] bc a9 [2] a2 b4 [2] a0 b5 [2] bb b3 [2] a7 b4 [2] bb 9b }

  condition:
    any of them
}