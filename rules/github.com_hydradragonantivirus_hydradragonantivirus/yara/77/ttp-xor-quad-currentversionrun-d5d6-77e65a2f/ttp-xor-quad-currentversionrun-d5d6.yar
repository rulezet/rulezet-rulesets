rule TTP_XOR_QUAD_CurrentVersionRun_d5d6 {
  strings:
    $key_d5d6 = { 86 b9 [2] a2 b7 [2] 89 9b [2] a7 b9 [2] b3 a2 [2] bc b8 [2] a2 a5 [2] a0 a4 [2] bb a2 [2] a7 a5 [2] bb 8a }

  condition:
    any of them
}