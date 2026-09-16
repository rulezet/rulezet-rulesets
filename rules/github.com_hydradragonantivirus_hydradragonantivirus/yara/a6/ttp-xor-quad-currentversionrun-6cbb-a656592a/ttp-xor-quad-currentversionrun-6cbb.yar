rule TTP_XOR_QUAD_CurrentVersionRun_6cbb {
  strings:
    $key_6cbb = { 3f d4 [2] 1b da [2] 30 f6 [2] 1e d4 [2] 0a cf [2] 05 d5 [2] 1b c8 [2] 19 c9 [2] 02 cf [2] 1e c8 [2] 02 e7 }

  condition:
    any of them
}