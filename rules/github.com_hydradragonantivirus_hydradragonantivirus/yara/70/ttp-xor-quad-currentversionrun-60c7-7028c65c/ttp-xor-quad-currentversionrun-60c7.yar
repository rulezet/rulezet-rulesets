rule TTP_XOR_QUAD_CurrentVersionRun_60c7 {
  strings:
    $key_60c7 = { 33 a8 [2] 17 a6 [2] 3c 8a [2] 12 a8 [2] 06 b3 [2] 09 a9 [2] 17 b4 [2] 15 b5 [2] 0e b3 [2] 12 b4 [2] 0e 9b }

  condition:
    any of them
}