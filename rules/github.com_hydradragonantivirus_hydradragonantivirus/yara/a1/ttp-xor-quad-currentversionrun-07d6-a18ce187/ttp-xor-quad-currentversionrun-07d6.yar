rule TTP_XOR_QUAD_CurrentVersionRun_07d6 {
  strings:
    $key_07d6 = { 54 b9 [2] 70 b7 [2] 5b 9b [2] 75 b9 [2] 61 a2 [2] 6e b8 [2] 70 a5 [2] 72 a4 [2] 69 a2 [2] 75 a5 [2] 69 8a }

  condition:
    any of them
}