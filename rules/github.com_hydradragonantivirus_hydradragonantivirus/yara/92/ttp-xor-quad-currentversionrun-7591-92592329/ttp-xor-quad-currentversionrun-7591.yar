rule TTP_XOR_QUAD_CurrentVersionRun_7591 {
  strings:
    $key_7591 = { 26 fe [2] 02 f0 [2] 29 dc [2] 07 fe [2] 13 e5 [2] 1c ff [2] 02 e2 [2] 00 e3 [2] 1b e5 [2] 07 e2 [2] 1b cd }

  condition:
    any of them
}