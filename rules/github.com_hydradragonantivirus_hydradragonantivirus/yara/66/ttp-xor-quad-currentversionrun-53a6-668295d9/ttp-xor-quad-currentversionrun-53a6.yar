rule TTP_XOR_QUAD_CurrentVersionRun_53a6 {
  strings:
    $key_53a6 = { 00 c9 [2] 24 c7 [2] 0f eb [2] 21 c9 [2] 35 d2 [2] 3a c8 [2] 24 d5 [2] 26 d4 [2] 3d d2 [2] 21 d5 [2] 3d fa }

  condition:
    any of them
}