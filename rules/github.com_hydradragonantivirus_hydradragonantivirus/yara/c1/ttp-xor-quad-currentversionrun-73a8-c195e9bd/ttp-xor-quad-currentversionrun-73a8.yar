rule TTP_XOR_QUAD_CurrentVersionRun_73a8 {
  strings:
    $key_73a8 = { 20 c7 [2] 04 c9 [2] 2f e5 [2] 01 c7 [2] 15 dc [2] 1a c6 [2] 04 db [2] 06 da [2] 1d dc [2] 01 db [2] 1d f4 }

  condition:
    any of them
}