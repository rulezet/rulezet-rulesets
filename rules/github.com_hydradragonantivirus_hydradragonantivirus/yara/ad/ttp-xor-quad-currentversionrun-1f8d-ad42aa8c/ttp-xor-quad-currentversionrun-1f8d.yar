rule TTP_XOR_QUAD_CurrentVersionRun_1f8d {
  strings:
    $key_1f8d = { 4c e2 [2] 68 ec [2] 43 c0 [2] 6d e2 [2] 79 f9 [2] 76 e3 [2] 68 fe [2] 6a ff [2] 71 f9 [2] 6d fe [2] 71 d1 }

  condition:
    any of them
}