rule TTP_XOR_QUAD_CurrentVersionRun_10aa {
  strings:
    $key_10aa = { 43 c5 [2] 67 cb [2] 4c e7 [2] 62 c5 [2] 76 de [2] 79 c4 [2] 67 d9 [2] 65 d8 [2] 7e de [2] 62 d9 [2] 7e f6 }

  condition:
    any of them
}