rule TTP_XOR_QUAD_CurrentVersionRun_1fc6 {
  strings:
    $key_1fc6 = { 4c a9 [2] 68 a7 [2] 43 8b [2] 6d a9 [2] 79 b2 [2] 76 a8 [2] 68 b5 [2] 6a b4 [2] 71 b2 [2] 6d b5 [2] 71 9a }

  condition:
    any of them
}