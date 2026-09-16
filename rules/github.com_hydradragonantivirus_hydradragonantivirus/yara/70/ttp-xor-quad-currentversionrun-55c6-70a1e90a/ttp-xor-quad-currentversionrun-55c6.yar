rule TTP_XOR_QUAD_CurrentVersionRun_55c6 {
  strings:
    $key_55c6 = { 06 a9 [2] 22 a7 [2] 09 8b [2] 27 a9 [2] 33 b2 [2] 3c a8 [2] 22 b5 [2] 20 b4 [2] 3b b2 [2] 27 b5 [2] 3b 9a }

  condition:
    any of them
}