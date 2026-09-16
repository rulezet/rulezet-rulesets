rule TTP_XOR_QUAD_CurrentVersionRun_67b5 {
  strings:
    $key_67b5 = { 34 da [2] 10 d4 [2] 3b f8 [2] 15 da [2] 01 c1 [2] 0e db [2] 10 c6 [2] 12 c7 [2] 09 c1 [2] 15 c6 [2] 09 e9 }

  condition:
    any of them
}