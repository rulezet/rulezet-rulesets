rule TTP_XOR_QUAD_CurrentVersionRun_67d6 {
  strings:
    $key_67d6 = { 34 b9 [2] 10 b7 [2] 3b 9b [2] 15 b9 [2] 01 a2 [2] 0e b8 [2] 10 a5 [2] 12 a4 [2] 09 a2 [2] 15 a5 [2] 09 8a }

  condition:
    any of them
}