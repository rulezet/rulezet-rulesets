rule TTP_XOR_QUAD_CurrentVersionRun_4e8d {
  strings:
    $key_4e8d = { 1d e2 [2] 39 ec [2] 12 c0 [2] 3c e2 [2] 28 f9 [2] 27 e3 [2] 39 fe [2] 3b ff [2] 20 f9 [2] 3c fe [2] 20 d1 }

  condition:
    any of them
}