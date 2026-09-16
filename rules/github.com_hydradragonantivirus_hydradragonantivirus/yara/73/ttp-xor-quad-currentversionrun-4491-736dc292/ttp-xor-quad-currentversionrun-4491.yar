rule TTP_XOR_QUAD_CurrentVersionRun_4491 {
  strings:
    $key_4491 = { 17 fe [2] 33 f0 [2] 18 dc [2] 36 fe [2] 22 e5 [2] 2d ff [2] 33 e2 [2] 31 e3 [2] 2a e5 [2] 36 e2 [2] 2a cd }

  condition:
    any of them
}