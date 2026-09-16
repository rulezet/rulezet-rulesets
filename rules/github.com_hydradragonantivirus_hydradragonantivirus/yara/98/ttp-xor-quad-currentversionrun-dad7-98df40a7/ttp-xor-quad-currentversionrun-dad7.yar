rule TTP_XOR_QUAD_CurrentVersionRun_dad7 {
  strings:
    $key_dad7 = { 89 b8 [2] ad b6 [2] 86 9a [2] a8 b8 [2] bc a3 [2] b3 b9 [2] ad a4 [2] af a5 [2] b4 a3 [2] a8 a4 [2] b4 8b }

  condition:
    any of them
}