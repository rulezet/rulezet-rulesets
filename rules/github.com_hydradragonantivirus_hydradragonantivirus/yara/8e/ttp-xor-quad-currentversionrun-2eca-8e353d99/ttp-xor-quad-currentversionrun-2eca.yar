rule TTP_XOR_QUAD_CurrentVersionRun_2eca {
  strings:
    $key_2eca = { 7d a5 [2] 59 ab [2] 72 87 [2] 5c a5 [2] 48 be [2] 47 a4 [2] 59 b9 [2] 5b b8 [2] 40 be [2] 5c b9 [2] 40 96 }

  condition:
    any of them
}