rule TTP_XOR_QUAD_CurrentVersionRun_22c6 {
  strings:
    $key_22c6 = { 71 a9 [2] 55 a7 [2] 7e 8b [2] 50 a9 [2] 44 b2 [2] 4b a8 [2] 55 b5 [2] 57 b4 [2] 4c b2 [2] 50 b5 [2] 4c 9a }

  condition:
    any of them
}