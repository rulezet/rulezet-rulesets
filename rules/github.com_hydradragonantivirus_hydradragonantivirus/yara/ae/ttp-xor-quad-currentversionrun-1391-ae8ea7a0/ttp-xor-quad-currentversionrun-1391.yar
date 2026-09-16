rule TTP_XOR_QUAD_CurrentVersionRun_1391 {
  strings:
    $key_1391 = { 40 fe [2] 64 f0 [2] 4f dc [2] 61 fe [2] 75 e5 [2] 7a ff [2] 64 e2 [2] 66 e3 [2] 7d e5 [2] 61 e2 [2] 7d cd }

  condition:
    any of them
}