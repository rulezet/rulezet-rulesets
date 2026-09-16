rule TTP_XOR_QUAD_CurrentVersionRun_2786 {
  strings:
    $key_2786 = { 74 e9 [2] 50 e7 [2] 7b cb [2] 55 e9 [2] 41 f2 [2] 4e e8 [2] 50 f5 [2] 52 f4 [2] 49 f2 [2] 55 f5 [2] 49 da }

  condition:
    any of them
}