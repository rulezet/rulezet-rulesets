rule TTP_XOR_QUAD_CurrentVersionRun_77a8 {
  strings:
    $key_77a8 = { 24 c7 [2] 00 c9 [2] 2b e5 [2] 05 c7 [2] 11 dc [2] 1e c6 [2] 00 db [2] 02 da [2] 19 dc [2] 05 db [2] 19 f4 }

  condition:
    any of them
}