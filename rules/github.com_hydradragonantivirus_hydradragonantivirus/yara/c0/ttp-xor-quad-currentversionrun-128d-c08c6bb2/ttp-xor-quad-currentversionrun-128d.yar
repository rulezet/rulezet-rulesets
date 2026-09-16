rule TTP_XOR_QUAD_CurrentVersionRun_128d {
  strings:
    $key_128d = { 41 e2 [2] 65 ec [2] 4e c0 [2] 60 e2 [2] 74 f9 [2] 7b e3 [2] 65 fe [2] 67 ff [2] 7c f9 [2] 60 fe [2] 7c d1 }

  condition:
    any of them
}