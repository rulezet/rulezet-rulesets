rule TTP_XOR_QUAD_CurrentVersionRun_3bd6 {
  strings:
    $key_3bd6 = { 68 b9 [2] 4c b7 [2] 67 9b [2] 49 b9 [2] 5d a2 [2] 52 b8 [2] 4c a5 [2] 4e a4 [2] 55 a2 [2] 49 a5 [2] 55 8a }

  condition:
    any of them
}