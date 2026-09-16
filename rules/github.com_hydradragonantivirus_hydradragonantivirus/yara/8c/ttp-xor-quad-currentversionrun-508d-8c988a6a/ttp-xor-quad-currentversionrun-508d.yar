rule TTP_XOR_QUAD_CurrentVersionRun_508d {
  strings:
    $key_508d = { 03 e2 [2] 27 ec [2] 0c c0 [2] 22 e2 [2] 36 f9 [2] 39 e3 [2] 27 fe [2] 25 ff [2] 3e f9 [2] 22 fe [2] 3e d1 }

  condition:
    any of them
}