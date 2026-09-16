rule TTP_XOR_QUAD_CurrentVersionRun_34c6 {
  strings:
    $key_34c6 = { 67 a9 [2] 43 a7 [2] 68 8b [2] 46 a9 [2] 52 b2 [2] 5d a8 [2] 43 b5 [2] 41 b4 [2] 5a b2 [2] 46 b5 [2] 5a 9a }

  condition:
    any of them
}