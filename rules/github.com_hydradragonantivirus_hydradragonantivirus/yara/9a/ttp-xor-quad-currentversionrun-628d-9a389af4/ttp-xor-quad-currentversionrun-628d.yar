rule TTP_XOR_QUAD_CurrentVersionRun_628d {
  strings:
    $key_628d = { 31 e2 [2] 15 ec [2] 3e c0 [2] 10 e2 [2] 04 f9 [2] 0b e3 [2] 15 fe [2] 17 ff [2] 0c f9 [2] 10 fe [2] 0c d1 }

  condition:
    any of them
}