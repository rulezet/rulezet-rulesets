rule TTP_XOR_QUAD_CurrentVersionRun_7491 {
  strings:
    $key_7491 = { 27 fe [2] 03 f0 [2] 28 dc [2] 06 fe [2] 12 e5 [2] 1d ff [2] 03 e2 [2] 01 e3 [2] 1a e5 [2] 06 e2 [2] 1a cd }

  condition:
    any of them
}