rule TTP_XOR_QUAD_CurrentVersionRun_71b4 {
  strings:
    $key_71b4 = { 22 db [2] 06 d5 [2] 2d f9 [2] 03 db [2] 17 c0 [2] 18 da [2] 06 c7 [2] 04 c6 [2] 1f c0 [2] 03 c7 [2] 1f e8 }

  condition:
    any of them
}