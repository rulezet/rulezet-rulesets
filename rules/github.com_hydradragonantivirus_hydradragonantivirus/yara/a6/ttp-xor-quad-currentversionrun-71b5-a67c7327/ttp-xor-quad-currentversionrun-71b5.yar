rule TTP_XOR_QUAD_CurrentVersionRun_71b5 {
  strings:
    $key_71b5 = { 22 da [2] 06 d4 [2] 2d f8 [2] 03 da [2] 17 c1 [2] 18 db [2] 06 c6 [2] 04 c7 [2] 1f c1 [2] 03 c6 [2] 1f e9 }

  condition:
    any of them
}