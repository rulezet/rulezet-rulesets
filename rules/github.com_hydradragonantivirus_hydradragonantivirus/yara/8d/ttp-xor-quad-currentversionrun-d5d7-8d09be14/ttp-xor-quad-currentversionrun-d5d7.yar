rule TTP_XOR_QUAD_CurrentVersionRun_d5d7 {
  strings:
    $key_d5d7 = { 86 b8 [2] a2 b6 [2] 89 9a [2] a7 b8 [2] b3 a3 [2] bc b9 [2] a2 a4 [2] a0 a5 [2] bb a3 [2] a7 a4 [2] bb 8b }

  condition:
    any of them
}