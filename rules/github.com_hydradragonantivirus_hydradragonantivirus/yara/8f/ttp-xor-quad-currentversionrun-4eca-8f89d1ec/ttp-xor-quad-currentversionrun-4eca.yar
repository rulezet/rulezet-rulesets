rule TTP_XOR_QUAD_CurrentVersionRun_4eca {
  strings:
    $key_4eca = { 1d a5 [2] 39 ab [2] 12 87 [2] 3c a5 [2] 28 be [2] 27 a4 [2] 39 b9 [2] 3b b8 [2] 20 be [2] 3c b9 [2] 20 96 }

  condition:
    any of them
}