rule TTP_XOR_QUAD_CurrentVersionRun_27b8 {
  strings:
    $key_27b8 = { 74 d7 [2] 50 d9 [2] 7b f5 [2] 55 d7 [2] 41 cc [2] 4e d6 [2] 50 cb [2] 52 ca [2] 49 cc [2] 55 cb [2] 49 e4 }

  condition:
    any of them
}