rule TTP_XOR_QUAD_CurrentVersionRun_17a8 {
  strings:
    $key_17a8 = { 44 c7 [2] 60 c9 [2] 4b e5 [2] 65 c7 [2] 71 dc [2] 7e c6 [2] 60 db [2] 62 da [2] 79 dc [2] 65 db [2] 79 f4 }

  condition:
    any of them
}