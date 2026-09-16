rule TTP_XOR_QUAD_CurrentVersionRun_4ec7 {
  strings:
    $key_4ec7 = { 1d a8 [2] 39 a6 [2] 12 8a [2] 3c a8 [2] 28 b3 [2] 27 a9 [2] 39 b4 [2] 3b b5 [2] 20 b3 [2] 3c b4 [2] 20 9b }

  condition:
    any of them
}