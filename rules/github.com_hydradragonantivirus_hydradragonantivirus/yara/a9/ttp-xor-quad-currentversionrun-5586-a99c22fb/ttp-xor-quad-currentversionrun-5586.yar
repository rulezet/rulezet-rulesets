rule TTP_XOR_QUAD_CurrentVersionRun_5586 {
  strings:
    $key_5586 = { 06 e9 [2] 22 e7 [2] 09 cb [2] 27 e9 [2] 33 f2 [2] 3c e8 [2] 22 f5 [2] 20 f4 [2] 3b f2 [2] 27 f5 [2] 3b da }

  condition:
    any of them
}