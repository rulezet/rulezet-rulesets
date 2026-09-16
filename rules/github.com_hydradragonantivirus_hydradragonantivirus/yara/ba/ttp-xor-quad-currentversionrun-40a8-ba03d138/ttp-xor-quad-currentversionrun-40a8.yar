rule TTP_XOR_QUAD_CurrentVersionRun_40a8 {
  strings:
    $key_40a8 = { 13 c7 [2] 37 c9 [2] 1c e5 [2] 32 c7 [2] 26 dc [2] 29 c6 [2] 37 db [2] 35 da [2] 2e dc [2] 32 db [2] 2e f4 }

  condition:
    any of them
}