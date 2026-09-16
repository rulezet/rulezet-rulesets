rule TTP_XOR_QUAD_CurrentVersionRun_24c6 {
  strings:
    $key_24c6 = { 77 a9 [2] 53 a7 [2] 78 8b [2] 56 a9 [2] 42 b2 [2] 4d a8 [2] 53 b5 [2] 51 b4 [2] 4a b2 [2] 56 b5 [2] 4a 9a }

  condition:
    any of them
}