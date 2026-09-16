rule TTP_XOR_QUAD_CurrentVersionRun_fcbb {
  strings:
    $key_fcbb = { af d4 [2] 8b da [2] a0 f6 [2] 8e d4 [2] 9a cf [2] 95 d5 [2] 8b c8 [2] 89 c9 [2] 92 cf [2] 8e c8 [2] 92 e7 }

  condition:
    any of them
}