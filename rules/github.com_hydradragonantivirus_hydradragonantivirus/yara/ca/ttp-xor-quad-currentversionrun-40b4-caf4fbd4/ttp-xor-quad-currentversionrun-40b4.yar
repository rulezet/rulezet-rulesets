rule TTP_XOR_QUAD_CurrentVersionRun_40b4 {
  strings:
    $key_40b4 = { 13 db [2] 37 d5 [2] 1c f9 [2] 32 db [2] 26 c0 [2] 29 da [2] 37 c7 [2] 35 c6 [2] 2e c0 [2] 32 c7 [2] 2e e8 }

  condition:
    any of them
}