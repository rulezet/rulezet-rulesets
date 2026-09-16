rule TTP_XOR_QUAD_CurrentVersionRun_1ec6 {
  strings:
    $key_1ec6 = { 4d a9 [2] 69 a7 [2] 42 8b [2] 6c a9 [2] 78 b2 [2] 77 a8 [2] 69 b5 [2] 6b b4 [2] 70 b2 [2] 6c b5 [2] 70 9a }

  condition:
    any of them
}