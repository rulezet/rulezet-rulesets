rule TTP_XOR_QUAD_CurrentVersionRun_e3b5 {
  strings:
    $key_e3b5 = { b0 da [2] 94 d4 [2] bf f8 [2] 91 da [2] 85 c1 [2] 8a db [2] 94 c6 [2] 96 c7 [2] 8d c1 [2] 91 c6 [2] 8d e9 }

  condition:
    any of them
}