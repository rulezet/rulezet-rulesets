rule TTP_XOR_QUAD_CurrentVersionRun_038d {
  strings:
    $key_038d = { 50 e2 [2] 74 ec [2] 5f c0 [2] 71 e2 [2] 65 f9 [2] 6a e3 [2] 74 fe [2] 76 ff [2] 6d f9 [2] 71 fe [2] 6d d1 }

  condition:
    any of them
}