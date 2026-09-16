rule TTP_XOR_QUAD_CurrentVersionRun_24d6 {
  strings:
    $key_24d6 = { 77 b9 [2] 53 b7 [2] 78 9b [2] 56 b9 [2] 42 a2 [2] 4d b8 [2] 53 a5 [2] 51 a4 [2] 4a a2 [2] 56 a5 [2] 4a 8a }

  condition:
    any of them
}