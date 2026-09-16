rule TTP_XOR_QUAD_CurrentVersionRun_31a8 {
  strings:
    $key_31a8 = { 62 c7 [2] 46 c9 [2] 6d e5 [2] 43 c7 [2] 57 dc [2] 58 c6 [2] 46 db [2] 44 da [2] 5f dc [2] 43 db [2] 5f f4 }

  condition:
    any of them
}