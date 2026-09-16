rule TTP_XOR_QUAD_CurrentVersionRun_20aa {
  strings:
    $key_20aa = { 73 c5 [2] 57 cb [2] 7c e7 [2] 52 c5 [2] 46 de [2] 49 c4 [2] 57 d9 [2] 55 d8 [2] 4e de [2] 52 d9 [2] 4e f6 }

  condition:
    any of them
}