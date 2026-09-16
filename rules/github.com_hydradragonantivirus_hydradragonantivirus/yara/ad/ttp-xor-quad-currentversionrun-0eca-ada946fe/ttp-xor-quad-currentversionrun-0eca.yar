rule TTP_XOR_QUAD_CurrentVersionRun_0eca {
  strings:
    $key_0eca = { 5d a5 [2] 79 ab [2] 52 87 [2] 7c a5 [2] 68 be [2] 67 a4 [2] 79 b9 [2] 7b b8 [2] 60 be [2] 7c b9 [2] 60 96 }

  condition:
    any of them
}