rule TTP_XOR_QUAD_CurrentVersionRun_17c6 {
  strings:
    $key_17c6 = { 44 a9 [2] 60 a7 [2] 4b 8b [2] 65 a9 [2] 71 b2 [2] 7e a8 [2] 60 b5 [2] 62 b4 [2] 79 b2 [2] 65 b5 [2] 79 9a }

  condition:
    any of them
}