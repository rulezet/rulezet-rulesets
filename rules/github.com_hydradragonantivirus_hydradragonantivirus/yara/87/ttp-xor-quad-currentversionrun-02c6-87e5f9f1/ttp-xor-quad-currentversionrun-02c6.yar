rule TTP_XOR_QUAD_CurrentVersionRun_02c6 {
  strings:
    $key_02c6 = { 51 a9 [2] 75 a7 [2] 5e 8b [2] 70 a9 [2] 64 b2 [2] 6b a8 [2] 75 b5 [2] 77 b4 [2] 6c b2 [2] 70 b5 [2] 6c 9a }

  condition:
    any of them
}