rule TTP_XOR_QUAD_CurrentVersionRun_26aa {
  strings:
    $key_26aa = { 75 c5 [2] 51 cb [2] 7a e7 [2] 54 c5 [2] 40 de [2] 4f c4 [2] 51 d9 [2] 53 d8 [2] 48 de [2] 54 d9 [2] 48 f6 }

  condition:
    any of them
}