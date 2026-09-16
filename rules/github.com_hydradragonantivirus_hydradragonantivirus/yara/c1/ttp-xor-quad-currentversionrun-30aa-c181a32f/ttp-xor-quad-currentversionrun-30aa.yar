rule TTP_XOR_QUAD_CurrentVersionRun_30aa {
  strings:
    $key_30aa = { 63 c5 [2] 47 cb [2] 6c e7 [2] 42 c5 [2] 56 de [2] 59 c4 [2] 47 d9 [2] 45 d8 [2] 5e de [2] 42 d9 [2] 5e f6 }

  condition:
    any of them
}