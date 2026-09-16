rule TTP_XOR_QUAD_CurrentVersionRun_7391 {
  strings:
    $key_7391 = { 20 fe [2] 04 f0 [2] 2f dc [2] 01 fe [2] 15 e5 [2] 1a ff [2] 04 e2 [2] 06 e3 [2] 1d e5 [2] 01 e2 [2] 1d cd }

  condition:
    any of them
}