rule TTP_XOR_QUAD_CurrentVersionRun_76c7 {
  strings:
    $key_76c7 = { 25 a8 [2] 01 a6 [2] 2a 8a [2] 04 a8 [2] 10 b3 [2] 1f a9 [2] 01 b4 [2] 03 b5 [2] 18 b3 [2] 04 b4 [2] 18 9b }

  condition:
    any of them
}