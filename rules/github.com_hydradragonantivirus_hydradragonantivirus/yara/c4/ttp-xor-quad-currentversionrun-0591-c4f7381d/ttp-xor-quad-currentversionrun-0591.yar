rule TTP_XOR_QUAD_CurrentVersionRun_0591 {
  strings:
    $key_0591 = { 56 fe [2] 72 f0 [2] 59 dc [2] 77 fe [2] 63 e5 [2] 6c ff [2] 72 e2 [2] 70 e3 [2] 6b e5 [2] 77 e2 [2] 6b cd }

  condition:
    any of them
}