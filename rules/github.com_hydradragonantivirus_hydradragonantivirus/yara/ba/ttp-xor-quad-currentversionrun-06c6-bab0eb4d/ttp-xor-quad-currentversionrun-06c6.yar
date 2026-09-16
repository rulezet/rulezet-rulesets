rule TTP_XOR_QUAD_CurrentVersionRun_06c6 {
  strings:
    $key_06c6 = { 55 a9 [2] 71 a7 [2] 5a 8b [2] 74 a9 [2] 60 b2 [2] 6f a8 [2] 71 b5 [2] 73 b4 [2] 68 b2 [2] 74 b5 [2] 68 9a }

  condition:
    any of them
}