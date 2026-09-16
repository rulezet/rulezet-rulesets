rule TTP_XOR_QUAD_CurrentVersionRun_35aa {
  strings:
    $key_35aa = { 66 c5 [2] 42 cb [2] 69 e7 [2] 47 c5 [2] 53 de [2] 5c c4 [2] 42 d9 [2] 40 d8 [2] 5b de [2] 47 d9 [2] 5b f6 }

  condition:
    any of them
}