rule TTP_XOR_QUAD_CurrentVersionRun_60c6 {
  strings:
    $key_60c6 = { 33 a9 [2] 17 a7 [2] 3c 8b [2] 12 a9 [2] 06 b2 [2] 09 a8 [2] 17 b5 [2] 15 b4 [2] 0e b2 [2] 12 b5 [2] 0e 9a }

  condition:
    any of them
}