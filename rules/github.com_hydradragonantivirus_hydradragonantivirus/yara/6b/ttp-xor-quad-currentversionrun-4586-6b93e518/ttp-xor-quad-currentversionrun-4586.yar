rule TTP_XOR_QUAD_CurrentVersionRun_4586 {
  strings:
    $key_4586 = { 16 e9 [2] 32 e7 [2] 19 cb [2] 37 e9 [2] 23 f2 [2] 2c e8 [2] 32 f5 [2] 30 f4 [2] 2b f2 [2] 37 f5 [2] 2b da }

  condition:
    any of them
}