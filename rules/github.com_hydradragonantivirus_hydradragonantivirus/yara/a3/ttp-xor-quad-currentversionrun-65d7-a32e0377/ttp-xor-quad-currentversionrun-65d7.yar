rule TTP_XOR_QUAD_CurrentVersionRun_65d7 {
  strings:
    $key_65d7 = { 36 b8 [2] 12 b6 [2] 39 9a [2] 17 b8 [2] 03 a3 [2] 0c b9 [2] 12 a4 [2] 10 a5 [2] 0b a3 [2] 17 a4 [2] 0b 8b }

  condition:
    any of them
}