rule TTP_XOR_QUAD_CurrentVersionRun_33a8 {
  strings:
    $key_33a8 = { 60 c7 [2] 44 c9 [2] 6f e5 [2] 41 c7 [2] 55 dc [2] 5a c6 [2] 44 db [2] 46 da [2] 5d dc [2] 41 db [2] 5d f4 }

  condition:
    any of them
}