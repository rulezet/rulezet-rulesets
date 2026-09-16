rule TTP_XOR_QUAD_CurrentVersionRun_42a8 {
  strings:
    $key_42a8 = { 11 c7 [2] 35 c9 [2] 1e e5 [2] 30 c7 [2] 24 dc [2] 2b c6 [2] 35 db [2] 37 da [2] 2c dc [2] 30 db [2] 2c f4 }

  condition:
    any of them
}