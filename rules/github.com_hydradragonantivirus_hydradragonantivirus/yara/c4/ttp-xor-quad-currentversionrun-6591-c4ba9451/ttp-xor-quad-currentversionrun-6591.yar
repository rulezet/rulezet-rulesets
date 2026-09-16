rule TTP_XOR_QUAD_CurrentVersionRun_6591 {
  strings:
    $key_6591 = { 36 fe [2] 12 f0 [2] 39 dc [2] 17 fe [2] 03 e5 [2] 0c ff [2] 12 e2 [2] 10 e3 [2] 0b e5 [2] 17 e2 [2] 0b cd }

  condition:
    any of them
}