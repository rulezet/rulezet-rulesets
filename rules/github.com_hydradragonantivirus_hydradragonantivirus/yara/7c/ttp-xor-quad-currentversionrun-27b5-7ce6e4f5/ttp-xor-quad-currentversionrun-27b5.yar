rule TTP_XOR_QUAD_CurrentVersionRun_27b5 {
  strings:
    $key_27b5 = { 74 da [2] 50 d4 [2] 7b f8 [2] 55 da [2] 41 c1 [2] 4e db [2] 50 c6 [2] 52 c7 [2] 49 c1 [2] 55 c6 [2] 49 e9 }

  condition:
    any of them
}