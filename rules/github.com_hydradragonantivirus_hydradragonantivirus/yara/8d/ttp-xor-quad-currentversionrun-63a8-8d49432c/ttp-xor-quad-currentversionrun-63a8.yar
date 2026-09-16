rule TTP_XOR_QUAD_CurrentVersionRun_63a8 {
  strings:
    $key_63a8 = { 30 c7 [2] 14 c9 [2] 3f e5 [2] 11 c7 [2] 05 dc [2] 0a c6 [2] 14 db [2] 16 da [2] 0d dc [2] 11 db [2] 0d f4 }

  condition:
    any of them
}