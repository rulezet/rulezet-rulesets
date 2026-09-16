rule TTP_XOR_QUAD_CurrentVersionRun_5f8d {
  strings:
    $key_5f8d = { 0c e2 [2] 28 ec [2] 03 c0 [2] 2d e2 [2] 39 f9 [2] 36 e3 [2] 28 fe [2] 2a ff [2] 31 f9 [2] 2d fe [2] 31 d1 }

  condition:
    any of them
}