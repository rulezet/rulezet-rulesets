rule TTP_XOR_QUAD_CurrentVersionRun_538b {
  strings:
    $key_538b = { 00 e4 [2] 24 ea [2] 0f c6 [2] 21 e4 [2] 35 ff [2] 3a e5 [2] 24 f8 [2] 26 f9 [2] 3d ff [2] 21 f8 [2] 3d d7 }

  condition:
    any of them
}