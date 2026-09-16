rule TTP_XOR_QUAD_CurrentVersionRun_52d7 {
  strings:
    $key_52d7 = { 01 b8 [2] 25 b6 [2] 0e 9a [2] 20 b8 [2] 34 a3 [2] 3b b9 [2] 25 a4 [2] 27 a5 [2] 3c a3 [2] 20 a4 [2] 3c 8b }

  condition:
    any of them
}