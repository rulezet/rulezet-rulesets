rule TTP_XOR_QUAD_CurrentVersionRun_718d {
  strings:
    $key_718d = { 22 e2 [2] 06 ec [2] 2d c0 [2] 03 e2 [2] 17 f9 [2] 18 e3 [2] 06 fe [2] 04 ff [2] 1f f9 [2] 03 fe [2] 1f d1 }

  condition:
    any of them
}