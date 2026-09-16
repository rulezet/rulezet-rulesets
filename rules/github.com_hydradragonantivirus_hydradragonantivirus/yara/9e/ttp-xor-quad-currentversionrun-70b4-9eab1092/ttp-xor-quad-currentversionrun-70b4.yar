rule TTP_XOR_QUAD_CurrentVersionRun_70b4 {
  strings:
    $key_70b4 = { 23 db [2] 07 d5 [2] 2c f9 [2] 02 db [2] 16 c0 [2] 19 da [2] 07 c7 [2] 05 c6 [2] 1e c0 [2] 02 c7 [2] 1e e8 }

  condition:
    any of them
}