rule TTP_XOR_QUAD_CurrentVersionRun_2fc6 {
  strings:
    $key_2fc6 = { 7c a9 [2] 58 a7 [2] 73 8b [2] 5d a9 [2] 49 b2 [2] 46 a8 [2] 58 b5 [2] 5a b4 [2] 41 b2 [2] 5d b5 [2] 41 9a }

  condition:
    any of them
}