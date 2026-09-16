rule TTP_XOR_QUAD_CurrentVersionRun_32aa {
  strings:
    $key_32aa = { 61 c5 [2] 45 cb [2] 6e e7 [2] 40 c5 [2] 54 de [2] 5b c4 [2] 45 d9 [2] 47 d8 [2] 5c de [2] 40 d9 [2] 5c f6 }

  condition:
    any of them
}