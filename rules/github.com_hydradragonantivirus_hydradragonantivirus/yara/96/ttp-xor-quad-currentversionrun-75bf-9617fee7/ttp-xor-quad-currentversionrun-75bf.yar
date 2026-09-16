rule TTP_XOR_QUAD_CurrentVersionRun_75bf {
  strings:
    $key_75bf = { 26 d0 [2] 02 de [2] 29 f2 [2] 07 d0 [2] 13 cb [2] 1c d1 [2] 02 cc [2] 00 cd [2] 1b cb [2] 07 cc [2] 1b e3 }

  condition:
    any of them
}