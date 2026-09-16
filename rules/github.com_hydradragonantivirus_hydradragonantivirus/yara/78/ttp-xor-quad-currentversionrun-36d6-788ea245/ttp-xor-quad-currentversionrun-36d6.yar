rule TTP_XOR_QUAD_CurrentVersionRun_36d6 {
  strings:
    $key_36d6 = { 65 b9 [2] 41 b7 [2] 6a 9b [2] 44 b9 [2] 50 a2 [2] 5f b8 [2] 41 a5 [2] 43 a4 [2] 58 a2 [2] 44 a5 [2] 58 8a }

  condition:
    any of them
}