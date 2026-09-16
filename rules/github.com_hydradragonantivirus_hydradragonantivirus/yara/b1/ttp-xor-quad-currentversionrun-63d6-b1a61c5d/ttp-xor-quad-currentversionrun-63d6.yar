rule TTP_XOR_QUAD_CurrentVersionRun_63d6 {
  strings:
    $key_63d6 = { 30 b9 [2] 14 b7 [2] 3f 9b [2] 11 b9 [2] 05 a2 [2] 0a b8 [2] 14 a5 [2] 16 a4 [2] 0d a2 [2] 11 a5 [2] 0d 8a }

  condition:
    any of them
}