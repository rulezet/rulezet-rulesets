rule TTP_XOR_QUAD_CurrentVersionRun_37aa {
  strings:
    $key_37aa = { 64 c5 [2] 40 cb [2] 6b e7 [2] 45 c5 [2] 51 de [2] 5e c4 [2] 40 d9 [2] 42 d8 [2] 59 de [2] 45 d9 [2] 59 f6 }

  condition:
    any of them
}