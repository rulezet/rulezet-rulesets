rule TTP_XOR_QUAD_CurrentVersionRun_3391 {
  strings:
    $key_3391 = { 60 fe [2] 44 f0 [2] 6f dc [2] 41 fe [2] 55 e5 [2] 5a ff [2] 44 e2 [2] 46 e3 [2] 5d e5 [2] 41 e2 [2] 5d cd }

  condition:
    any of them
}