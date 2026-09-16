rule TTP_XOR_QUAD_CurrentVersionRun_70a8 {
  strings:
    $key_70a8 = { 23 c7 [2] 07 c9 [2] 2c e5 [2] 02 c7 [2] 16 dc [2] 19 c6 [2] 07 db [2] 05 da [2] 1e dc [2] 02 db [2] 1e f4 }

  condition:
    any of them
}