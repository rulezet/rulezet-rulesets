rule TTP_XOR_QUAD_CurrentVersionRun_1ed6 {
  strings:
    $key_1ed6 = { 4d b9 [2] 69 b7 [2] 42 9b [2] 6c b9 [2] 78 a2 [2] 77 b8 [2] 69 a5 [2] 6b a4 [2] 70 a2 [2] 6c a5 [2] 70 8a }

  condition:
    any of them
}