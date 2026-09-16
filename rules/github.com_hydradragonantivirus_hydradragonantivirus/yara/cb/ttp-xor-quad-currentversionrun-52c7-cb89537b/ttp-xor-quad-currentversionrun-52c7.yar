rule TTP_XOR_QUAD_CurrentVersionRun_52c7 {
  strings:
    $key_52c7 = { 01 a8 [2] 25 a6 [2] 0e 8a [2] 20 a8 [2] 34 b3 [2] 3b a9 [2] 25 b4 [2] 27 b5 [2] 3c b3 [2] 20 b4 [2] 3c 9b }

  condition:
    any of them
}