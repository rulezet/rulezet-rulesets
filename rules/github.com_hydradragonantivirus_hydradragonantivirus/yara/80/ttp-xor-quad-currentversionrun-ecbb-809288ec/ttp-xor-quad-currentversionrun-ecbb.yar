rule TTP_XOR_QUAD_CurrentVersionRun_ecbb {
  strings:
    $key_ecbb = { bf d4 [2] 9b da [2] b0 f6 [2] 9e d4 [2] 8a cf [2] 85 d5 [2] 9b c8 [2] 99 c9 [2] 82 cf [2] 9e c8 [2] 82 e7 }

  condition:
    any of them
}