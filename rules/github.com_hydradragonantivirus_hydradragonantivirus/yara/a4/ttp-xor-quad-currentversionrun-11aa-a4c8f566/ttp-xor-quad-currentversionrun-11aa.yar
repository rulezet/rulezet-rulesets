rule TTP_XOR_QUAD_CurrentVersionRun_11aa {
  strings:
    $key_11aa = { 42 c5 [2] 66 cb [2] 4d e7 [2] 63 c5 [2] 77 de [2] 78 c4 [2] 66 d9 [2] 64 d8 [2] 7f de [2] 63 d9 [2] 7f f6 }

  condition:
    any of them
}