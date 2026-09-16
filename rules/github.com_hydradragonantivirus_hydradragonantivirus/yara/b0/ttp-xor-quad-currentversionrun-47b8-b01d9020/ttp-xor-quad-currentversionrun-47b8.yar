rule TTP_XOR_QUAD_CurrentVersionRun_47b8 {
  strings:
    $key_47b8 = { 14 d7 [2] 30 d9 [2] 1b f5 [2] 35 d7 [2] 21 cc [2] 2e d6 [2] 30 cb [2] 32 ca [2] 29 cc [2] 35 cb [2] 29 e4 }

  condition:
    any of them
}