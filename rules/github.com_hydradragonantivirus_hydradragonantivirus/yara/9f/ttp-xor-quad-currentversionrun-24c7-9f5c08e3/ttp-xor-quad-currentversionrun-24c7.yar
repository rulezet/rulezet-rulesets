rule TTP_XOR_QUAD_CurrentVersionRun_24c7 {
  strings:
    $key_24c7 = { 77 a8 [2] 53 a6 [2] 78 8a [2] 56 a8 [2] 42 b3 [2] 4d a9 [2] 53 b4 [2] 51 b5 [2] 4a b3 [2] 56 b4 [2] 4a 9b }

  condition:
    any of them
}