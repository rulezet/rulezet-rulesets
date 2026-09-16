rule TTP_XOR_QUAD_CurrentVersionRun_34c7 {
  strings:
    $key_34c7 = { 67 a8 [2] 43 a6 [2] 68 8a [2] 46 a8 [2] 52 b3 [2] 5d a9 [2] 43 b4 [2] 41 b5 [2] 5a b3 [2] 46 b4 [2] 5a 9b }

  condition:
    any of them
}