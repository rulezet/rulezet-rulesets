rule TTP_XOR_QUAD_CurrentVersionRun_2ec7 {
  strings:
    $key_2ec7 = { 7d a8 [2] 59 a6 [2] 72 8a [2] 5c a8 [2] 48 b3 [2] 47 a9 [2] 59 b4 [2] 5b b5 [2] 40 b3 [2] 5c b4 [2] 40 9b }

  condition:
    any of them
}