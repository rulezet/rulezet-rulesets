rule TTP_XOR_QUAD_CurrentVersionRun_53a8 {
  strings:
    $key_53a8 = { 00 c7 [2] 24 c9 [2] 0f e5 [2] 21 c7 [2] 35 dc [2] 3a c6 [2] 24 db [2] 26 da [2] 3d dc [2] 21 db [2] 3d f4 }

  condition:
    any of them
}