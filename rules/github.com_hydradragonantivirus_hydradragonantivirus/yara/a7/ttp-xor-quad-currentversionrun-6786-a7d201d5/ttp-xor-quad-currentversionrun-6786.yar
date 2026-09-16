rule TTP_XOR_QUAD_CurrentVersionRun_6786 {
  strings:
    $key_6786 = { 34 e9 [2] 10 e7 [2] 3b cb [2] 15 e9 [2] 01 f2 [2] 0e e8 [2] 10 f5 [2] 12 f4 [2] 09 f2 [2] 15 f5 [2] 09 da }

  condition:
    any of them
}