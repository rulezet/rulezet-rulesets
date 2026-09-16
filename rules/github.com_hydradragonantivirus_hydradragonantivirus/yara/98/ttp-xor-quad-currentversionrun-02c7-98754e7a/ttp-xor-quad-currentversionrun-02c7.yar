rule TTP_XOR_QUAD_CurrentVersionRun_02c7 {
  strings:
    $key_02c7 = { 51 a8 [2] 75 a6 [2] 5e 8a [2] 70 a8 [2] 64 b3 [2] 6b a9 [2] 75 b4 [2] 77 b5 [2] 6c b3 [2] 70 b4 [2] 6c 9b }

  condition:
    any of them
}