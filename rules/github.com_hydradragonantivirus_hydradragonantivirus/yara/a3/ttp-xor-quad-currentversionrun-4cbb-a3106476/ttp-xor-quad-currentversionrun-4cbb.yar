rule TTP_XOR_QUAD_CurrentVersionRun_4cbb {
  strings:
    $key_4cbb = { 1f d4 [2] 3b da [2] 10 f6 [2] 3e d4 [2] 2a cf [2] 25 d5 [2] 3b c8 [2] 39 c9 [2] 22 cf [2] 3e c8 [2] 22 e7 }

  condition:
    any of them
}