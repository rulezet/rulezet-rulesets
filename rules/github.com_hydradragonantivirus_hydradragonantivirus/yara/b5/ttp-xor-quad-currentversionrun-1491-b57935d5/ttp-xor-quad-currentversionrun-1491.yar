rule TTP_XOR_QUAD_CurrentVersionRun_1491 {
  strings:
    $key_1491 = { 47 fe [2] 63 f0 [2] 48 dc [2] 66 fe [2] 72 e5 [2] 7d ff [2] 63 e2 [2] 61 e3 [2] 7a e5 [2] 66 e2 [2] 7a cd }

  condition:
    any of them
}