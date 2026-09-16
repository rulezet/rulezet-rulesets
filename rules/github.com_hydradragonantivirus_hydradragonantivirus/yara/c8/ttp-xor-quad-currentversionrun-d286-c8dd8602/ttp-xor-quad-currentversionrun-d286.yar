rule TTP_XOR_QUAD_CurrentVersionRun_d286 {
  strings:
    $key_d286 = { 81 e9 [2] a5 e7 [2] 8e cb [2] a0 e9 [2] b4 f2 [2] bb e8 [2] a5 f5 [2] a7 f4 [2] bc f2 [2] a0 f5 [2] bc da }

  condition:
    any of them
}