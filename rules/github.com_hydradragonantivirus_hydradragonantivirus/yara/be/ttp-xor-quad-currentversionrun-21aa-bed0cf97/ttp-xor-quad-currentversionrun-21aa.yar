rule TTP_XOR_QUAD_CurrentVersionRun_21aa {
  strings:
    $key_21aa = { 72 c5 [2] 56 cb [2] 7d e7 [2] 53 c5 [2] 47 de [2] 48 c4 [2] 56 d9 [2] 54 d8 [2] 4f de [2] 53 d9 [2] 4f f6 }

  condition:
    any of them
}