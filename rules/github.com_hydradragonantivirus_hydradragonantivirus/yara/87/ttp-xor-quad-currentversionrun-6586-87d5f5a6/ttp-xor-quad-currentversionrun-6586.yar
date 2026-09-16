rule TTP_XOR_QUAD_CurrentVersionRun_6586 {
  strings:
    $key_6586 = { 36 e9 [2] 12 e7 [2] 39 cb [2] 17 e9 [2] 03 f2 [2] 0c e8 [2] 12 f5 [2] 10 f4 [2] 0b f2 [2] 17 f5 [2] 0b da }

  condition:
    any of them
}