rule TTP_XOR_QUAD_CurrentVersionRun_5391 {
  strings:
    $key_5391 = { 00 fe [2] 24 f0 [2] 0f dc [2] 21 fe [2] 35 e5 [2] 3a ff [2] 24 e2 [2] 26 e3 [2] 3d e5 [2] 21 e2 [2] 3d cd }

  condition:
    any of them
}