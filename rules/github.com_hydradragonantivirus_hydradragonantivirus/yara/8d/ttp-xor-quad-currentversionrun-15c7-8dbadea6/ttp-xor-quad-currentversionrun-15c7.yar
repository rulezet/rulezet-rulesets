rule TTP_XOR_QUAD_CurrentVersionRun_15c7 {
  strings:
    $key_15c7 = { 46 a8 [2] 62 a6 [2] 49 8a [2] 67 a8 [2] 73 b3 [2] 7c a9 [2] 62 b4 [2] 60 b5 [2] 7b b3 [2] 67 b4 [2] 7b 9b }

  condition:
    any of them
}