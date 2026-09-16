rule TTP_XOR_QUAD_CurrentVersionRun_7bd6 {
  strings:
    $key_7bd6 = { 28 b9 [2] 0c b7 [2] 27 9b [2] 09 b9 [2] 1d a2 [2] 12 b8 [2] 0c a5 [2] 0e a4 [2] 15 a2 [2] 09 a5 [2] 15 8a }

  condition:
    any of them
}