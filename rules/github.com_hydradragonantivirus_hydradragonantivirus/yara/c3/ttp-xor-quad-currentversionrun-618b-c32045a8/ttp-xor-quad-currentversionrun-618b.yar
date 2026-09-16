rule TTP_XOR_QUAD_CurrentVersionRun_618b {
  strings:
    $key_618b = { 32 e4 [2] 16 ea [2] 3d c6 [2] 13 e4 [2] 07 ff [2] 08 e5 [2] 16 f8 [2] 14 f9 [2] 0f ff [2] 13 f8 [2] 0f d7 }

  condition:
    any of them
}