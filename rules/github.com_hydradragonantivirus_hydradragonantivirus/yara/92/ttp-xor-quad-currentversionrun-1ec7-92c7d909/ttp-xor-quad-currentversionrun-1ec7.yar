rule TTP_XOR_QUAD_CurrentVersionRun_1ec7 {
  strings:
    $key_1ec7 = { 4d a8 [2] 69 a6 [2] 42 8a [2] 6c a8 [2] 78 b3 [2] 77 a9 [2] 69 b4 [2] 6b b5 [2] 70 b3 [2] 6c b4 [2] 70 9b }

  condition:
    any of them
}