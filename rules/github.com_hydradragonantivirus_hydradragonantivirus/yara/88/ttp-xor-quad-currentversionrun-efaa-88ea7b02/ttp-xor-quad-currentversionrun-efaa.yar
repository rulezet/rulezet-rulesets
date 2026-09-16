rule TTP_XOR_QUAD_CurrentVersionRun_efaa {
  strings:
    $key_efaa = { bc c5 [2] 98 cb [2] b3 e7 [2] 9d c5 [2] 89 de [2] 86 c4 [2] 98 d9 [2] 9a d8 [2] 81 de [2] 9d d9 [2] 81 f6 }

  condition:
    any of them
}