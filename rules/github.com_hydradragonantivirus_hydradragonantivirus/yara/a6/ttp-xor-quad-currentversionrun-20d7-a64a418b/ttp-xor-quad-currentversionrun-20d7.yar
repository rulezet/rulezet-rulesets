rule TTP_XOR_QUAD_CurrentVersionRun_20d7 {
  strings:
    $key_20d7 = { 73 b8 [2] 57 b6 [2] 7c 9a [2] 52 b8 [2] 46 a3 [2] 49 b9 [2] 57 a4 [2] 55 a5 [2] 4e a3 [2] 52 a4 [2] 4e 8b }

  condition:
    any of them
}