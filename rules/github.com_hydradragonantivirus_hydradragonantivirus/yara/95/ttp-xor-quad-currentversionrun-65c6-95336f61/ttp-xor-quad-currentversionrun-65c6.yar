rule TTP_XOR_QUAD_CurrentVersionRun_65c6 {
  strings:
    $key_65c6 = { 36 a9 [2] 12 a7 [2] 39 8b [2] 17 a9 [2] 03 b2 [2] 0c a8 [2] 12 b5 [2] 10 b4 [2] 0b b2 [2] 17 b5 [2] 0b 9a }

  condition:
    any of them
}