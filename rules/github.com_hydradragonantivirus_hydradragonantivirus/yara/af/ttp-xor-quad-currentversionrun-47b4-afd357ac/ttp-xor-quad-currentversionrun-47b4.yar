rule TTP_XOR_QUAD_CurrentVersionRun_47b4 {
  strings:
    $key_47b4 = { 14 db [2] 30 d5 [2] 1b f9 [2] 35 db [2] 21 c0 [2] 2e da [2] 30 c7 [2] 32 c6 [2] 29 c0 [2] 35 c7 [2] 29 e8 }

  condition:
    any of them
}