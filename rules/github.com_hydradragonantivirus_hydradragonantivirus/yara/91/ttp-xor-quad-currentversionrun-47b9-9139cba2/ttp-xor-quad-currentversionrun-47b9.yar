rule TTP_XOR_QUAD_CurrentVersionRun_47b9 {
  strings:
    $key_47b9 = { 14 d6 [2] 30 d8 [2] 1b f4 [2] 35 d6 [2] 21 cd [2] 2e d7 [2] 30 ca [2] 32 cb [2] 29 cd [2] 35 ca [2] 29 e5 }

  condition:
    any of them
}