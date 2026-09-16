rule TTP_XOR_QUAD_CurrentVersionRun_41aa {
  strings:
    $key_41aa = { 12 c5 [2] 36 cb [2] 1d e7 [2] 33 c5 [2] 27 de [2] 28 c4 [2] 36 d9 [2] 34 d8 [2] 2f de [2] 33 d9 [2] 2f f6 }

  condition:
    any of them
}