rule TTP_XOR_QUAD_CurrentVersionRun_07d7 {
  strings:
    $key_07d7 = { 54 b8 [2] 70 b6 [2] 5b 9a [2] 75 b8 [2] 61 a3 [2] 6e b9 [2] 70 a4 [2] 72 a5 [2] 69 a3 [2] 75 a4 [2] 69 8b }

  condition:
    any of them
}