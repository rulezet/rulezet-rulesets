rule TTP_XOR_QUAD_CurrentVersionRun_15aa {
  strings:
    $key_15aa = { 46 c5 [2] 62 cb [2] 49 e7 [2] 67 c5 [2] 73 de [2] 7c c4 [2] 62 d9 [2] 60 d8 [2] 7b de [2] 67 d9 [2] 7b f6 }

  condition:
    any of them
}