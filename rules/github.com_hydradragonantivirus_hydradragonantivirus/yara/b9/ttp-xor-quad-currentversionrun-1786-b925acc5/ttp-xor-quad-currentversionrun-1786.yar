rule TTP_XOR_QUAD_CurrentVersionRun_1786 {
  strings:
    $key_1786 = { 44 e9 [2] 60 e7 [2] 4b cb [2] 65 e9 [2] 71 f2 [2] 7e e8 [2] 60 f5 [2] 62 f4 [2] 79 f2 [2] 65 f5 [2] 79 da }

  condition:
    any of them
}