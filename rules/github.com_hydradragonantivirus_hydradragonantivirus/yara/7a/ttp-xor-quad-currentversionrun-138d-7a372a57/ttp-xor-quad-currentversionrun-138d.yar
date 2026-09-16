rule TTP_XOR_QUAD_CurrentVersionRun_138d {
  strings:
    $key_138d = { 40 e2 [2] 64 ec [2] 4f c0 [2] 61 e2 [2] 75 f9 [2] 7a e3 [2] 64 fe [2] 66 ff [2] 7d f9 [2] 61 fe [2] 7d d1 }

  condition:
    any of them
}