rule TTP_XOR_QUAD_CurrentVersionRun_3ec6 {
  strings:
    $key_3ec6 = { 6d a9 [2] 49 a7 [2] 62 8b [2] 4c a9 [2] 58 b2 [2] 57 a8 [2] 49 b5 [2] 4b b4 [2] 50 b2 [2] 4c b5 [2] 50 9a }

  condition:
    any of them
}