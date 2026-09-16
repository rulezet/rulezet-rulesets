rule TTP_XOR_QUAD_CurrentVersionRun_2586 {
  strings:
    $key_2586 = { 76 e9 [2] 52 e7 [2] 79 cb [2] 57 e9 [2] 43 f2 [2] 4c e8 [2] 52 f5 [2] 50 f4 [2] 4b f2 [2] 57 f5 [2] 4b da }

  condition:
    any of them
}