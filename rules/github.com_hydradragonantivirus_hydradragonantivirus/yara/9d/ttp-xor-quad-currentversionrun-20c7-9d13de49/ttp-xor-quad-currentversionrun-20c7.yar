rule TTP_XOR_QUAD_CurrentVersionRun_20c7 {
  strings:
    $key_20c7 = { 73 a8 [2] 57 a6 [2] 7c 8a [2] 52 a8 [2] 46 b3 [2] 49 a9 [2] 57 b4 [2] 55 b5 [2] 4e b3 [2] 52 b4 [2] 4e 9b }

  condition:
    any of them
}