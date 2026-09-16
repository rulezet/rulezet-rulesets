rule TTP_XOR_QUAD_CurrentVersionRun_67d7 {
  strings:
    $key_67d7 = { 34 b8 [2] 10 b6 [2] 3b 9a [2] 15 b8 [2] 01 a3 [2] 0e b9 [2] 10 a4 [2] 12 a5 [2] 09 a3 [2] 15 a4 [2] 09 8b }

  condition:
    any of them
}