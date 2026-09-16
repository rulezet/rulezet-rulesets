rule TTP_XOR_QUAD_CurrentVersionRun_25d6 {
  strings:
    $key_25d6 = { 76 b9 [2] 52 b7 [2] 79 9b [2] 57 b9 [2] 43 a2 [2] 4c b8 [2] 52 a5 [2] 50 a4 [2] 4b a2 [2] 57 a5 [2] 4b 8a }

  condition:
    any of them
}