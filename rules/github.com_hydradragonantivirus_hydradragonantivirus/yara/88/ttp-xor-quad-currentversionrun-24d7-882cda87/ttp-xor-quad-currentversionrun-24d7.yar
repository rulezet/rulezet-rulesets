rule TTP_XOR_QUAD_CurrentVersionRun_24d7 {
  strings:
    $key_24d7 = { 77 b8 [2] 53 b6 [2] 78 9a [2] 56 b8 [2] 42 a3 [2] 4d b9 [2] 53 a4 [2] 51 a5 [2] 4a a3 [2] 56 a4 [2] 4a 8b }

  condition:
    any of them
}