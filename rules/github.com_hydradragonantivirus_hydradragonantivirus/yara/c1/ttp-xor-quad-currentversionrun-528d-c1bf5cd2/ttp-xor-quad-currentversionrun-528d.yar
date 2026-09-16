rule TTP_XOR_QUAD_CurrentVersionRun_528d {
  strings:
    $key_528d = { 01 e2 [2] 25 ec [2] 0e c0 [2] 20 e2 [2] 34 f9 [2] 3b e3 [2] 25 fe [2] 27 ff [2] 3c f9 [2] 20 fe [2] 3c d1 }

  condition:
    any of them
}