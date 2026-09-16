rule TTP_XOR_QUAD_CurrentVersionRun_31aa {
  strings:
    $key_31aa = { 62 c5 [2] 46 cb [2] 6d e7 [2] 43 c5 [2] 57 de [2] 58 c4 [2] 46 d9 [2] 44 d8 [2] 5f de [2] 43 d9 [2] 5f f6 }

  condition:
    any of them
}