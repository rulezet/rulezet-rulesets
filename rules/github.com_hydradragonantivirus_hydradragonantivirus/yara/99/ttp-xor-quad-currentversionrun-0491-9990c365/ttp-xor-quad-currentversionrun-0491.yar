rule TTP_XOR_QUAD_CurrentVersionRun_0491 {
  strings:
    $key_0491 = { 57 fe [2] 73 f0 [2] 58 dc [2] 76 fe [2] 62 e5 [2] 6d ff [2] 73 e2 [2] 71 e3 [2] 6a e5 [2] 76 e2 [2] 6a cd }

  condition:
    any of them
}