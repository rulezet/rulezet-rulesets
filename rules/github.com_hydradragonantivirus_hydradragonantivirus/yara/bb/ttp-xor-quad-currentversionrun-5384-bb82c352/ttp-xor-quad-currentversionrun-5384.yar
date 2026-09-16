rule TTP_XOR_QUAD_CurrentVersionRun_5384 {
  strings:
    $key_5384 = { 00 eb [2] 24 e5 [2] 0f c9 [2] 21 eb [2] 35 f0 [2] 3a ea [2] 24 f7 [2] 26 f6 [2] 3d f0 [2] 21 f7 [2] 3d d8 }

  condition:
    any of them
}