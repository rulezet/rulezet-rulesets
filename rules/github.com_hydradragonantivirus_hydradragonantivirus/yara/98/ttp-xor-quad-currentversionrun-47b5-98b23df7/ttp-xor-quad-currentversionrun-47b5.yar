rule TTP_XOR_QUAD_CurrentVersionRun_47b5 {
  strings:
    $key_47b5 = { 14 da [2] 30 d4 [2] 1b f8 [2] 35 da [2] 21 c1 [2] 2e db [2] 30 c6 [2] 32 c7 [2] 29 c1 [2] 35 c6 [2] 29 e9 }

  condition:
    any of them
}