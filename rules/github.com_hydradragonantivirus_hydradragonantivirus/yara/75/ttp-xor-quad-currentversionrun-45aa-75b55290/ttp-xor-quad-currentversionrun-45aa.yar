rule TTP_XOR_QUAD_CurrentVersionRun_45aa {
  strings:
    $key_45aa = { 16 c5 [2] 32 cb [2] 19 e7 [2] 37 c5 [2] 23 de [2] 2c c4 [2] 32 d9 [2] 30 d8 [2] 2b de [2] 37 d9 [2] 2b f6 }

  condition:
    any of them
}