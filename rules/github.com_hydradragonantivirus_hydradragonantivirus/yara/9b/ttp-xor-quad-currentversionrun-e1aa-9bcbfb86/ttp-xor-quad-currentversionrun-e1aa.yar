rule TTP_XOR_QUAD_CurrentVersionRun_e1aa {
  strings:
    $key_e1aa = { b2 c5 [2] 96 cb [2] bd e7 [2] 93 c5 [2] 87 de [2] 88 c4 [2] 96 d9 [2] 94 d8 [2] 8f de [2] 93 d9 [2] 8f f6 }

  condition:
    any of them
}