rule TTP_XOR_QUAD_CurrentVersionRun_71a8 {
  strings:
    $key_71a8 = { 22 c7 [2] 06 c9 [2] 2d e5 [2] 03 c7 [2] 17 dc [2] 18 c6 [2] 06 db [2] 04 da [2] 1f dc [2] 03 db [2] 1f f4 }

  condition:
    any of them
}