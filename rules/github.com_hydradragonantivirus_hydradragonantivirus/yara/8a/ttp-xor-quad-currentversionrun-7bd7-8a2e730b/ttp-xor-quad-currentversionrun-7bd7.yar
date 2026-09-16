rule TTP_XOR_QUAD_CurrentVersionRun_7bd7 {
  strings:
    $key_7bd7 = { 28 b8 [2] 0c b6 [2] 27 9a [2] 09 b8 [2] 1d a3 [2] 12 b9 [2] 0c a4 [2] 0e a5 [2] 15 a3 [2] 09 a4 [2] 15 8b }

  condition:
    any of them
}