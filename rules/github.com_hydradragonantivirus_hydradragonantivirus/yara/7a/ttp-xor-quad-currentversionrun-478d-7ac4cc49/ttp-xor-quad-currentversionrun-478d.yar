rule TTP_XOR_QUAD_CurrentVersionRun_478d {
  strings:
    $key_478d = { 14 e2 [2] 30 ec [2] 1b c0 [2] 35 e2 [2] 21 f9 [2] 2e e3 [2] 30 fe [2] 32 ff [2] 29 f9 [2] 35 fe [2] 29 d1 }

  condition:
    any of them
}