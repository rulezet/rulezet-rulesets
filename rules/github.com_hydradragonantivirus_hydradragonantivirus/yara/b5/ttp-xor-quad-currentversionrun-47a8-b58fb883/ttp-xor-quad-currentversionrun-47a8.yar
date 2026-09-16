rule TTP_XOR_QUAD_CurrentVersionRun_47a8 {
  strings:
    $key_47a8 = { 14 c7 [2] 30 c9 [2] 1b e5 [2] 35 c7 [2] 21 dc [2] 2e c6 [2] 30 db [2] 32 da [2] 29 dc [2] 35 db [2] 29 f4 }

  condition:
    any of them
}