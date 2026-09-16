rule TTP_XOR_QUAD_CurrentVersionRun_2cbb {
  strings:
    $key_2cbb = { 7f d4 [2] 5b da [2] 70 f6 [2] 5e d4 [2] 4a cf [2] 45 d5 [2] 5b c8 [2] 59 c9 [2] 42 cf [2] 5e c8 [2] 42 e7 }

  condition:
    any of them
}