rule TTP_XOR_QUAD_CurrentVersionRun_5e8d {
  strings:
    $key_5e8d = { 0d e2 [2] 29 ec [2] 02 c0 [2] 2c e2 [2] 38 f9 [2] 37 e3 [2] 29 fe [2] 2b ff [2] 30 f9 [2] 2c fe [2] 30 d1 }

  condition:
    any of them
}