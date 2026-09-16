rule TTP_XOR_QUAD_CurrentVersionRun_5591 {
  strings:
    $key_5591 = { 06 fe [2] 22 f0 [2] 09 dc [2] 27 fe [2] 33 e5 [2] 3c ff [2] 22 e2 [2] 20 e3 [2] 3b e5 [2] 27 e2 [2] 3b cd }

  condition:
    any of them
}