rule TTP_XOR_QUAD_CurrentVersionRun_44a8 {
  strings:
    $key_44a8 = { 17 c7 [2] 33 c9 [2] 18 e5 [2] 36 c7 [2] 22 dc [2] 2d c6 [2] 33 db [2] 31 da [2] 2a dc [2] 36 db [2] 2a f4 }

  condition:
    any of them
}