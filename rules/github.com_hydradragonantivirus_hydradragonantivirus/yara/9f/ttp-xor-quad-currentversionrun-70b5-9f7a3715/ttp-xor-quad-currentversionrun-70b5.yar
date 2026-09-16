rule TTP_XOR_QUAD_CurrentVersionRun_70b5 {
  strings:
    $key_70b5 = { 23 da [2] 07 d4 [2] 2c f8 [2] 02 da [2] 16 c1 [2] 19 db [2] 07 c6 [2] 05 c7 [2] 1e c1 [2] 02 c6 [2] 1e e9 }

  condition:
    any of them
}