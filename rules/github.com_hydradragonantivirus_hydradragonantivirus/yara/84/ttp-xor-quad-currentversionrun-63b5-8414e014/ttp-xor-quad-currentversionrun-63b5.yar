rule TTP_XOR_QUAD_CurrentVersionRun_63b5 {
  strings:
    $key_63b5 = { 30 da [2] 14 d4 [2] 3f f8 [2] 11 da [2] 05 c1 [2] 0a db [2] 14 c6 [2] 16 c7 [2] 0d c1 [2] 11 c6 [2] 0d e9 }

  condition:
    any of them
}