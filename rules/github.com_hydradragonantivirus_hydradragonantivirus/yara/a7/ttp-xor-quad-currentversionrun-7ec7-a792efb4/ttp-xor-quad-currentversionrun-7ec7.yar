rule TTP_XOR_QUAD_CurrentVersionRun_7ec7 {
  strings:
    $key_7ec7 = { 2d a8 [2] 09 a6 [2] 22 8a [2] 0c a8 [2] 18 b3 [2] 17 a9 [2] 09 b4 [2] 0b b5 [2] 10 b3 [2] 0c b4 [2] 10 9b }

  condition:
    any of them
}