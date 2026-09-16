rule TTP_XOR_QUAD_CurrentVersionRun_5cbb {
  strings:
    $key_5cbb = { 0f d4 [2] 2b da [2] 00 f6 [2] 2e d4 [2] 3a cf [2] 35 d5 [2] 2b c8 [2] 29 c9 [2] 32 cf [2] 2e c8 [2] 32 e7 }

  condition:
    any of them
}