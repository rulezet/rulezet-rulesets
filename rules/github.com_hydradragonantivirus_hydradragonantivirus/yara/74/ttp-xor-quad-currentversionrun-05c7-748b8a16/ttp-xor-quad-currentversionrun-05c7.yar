rule TTP_XOR_QUAD_CurrentVersionRun_05c7 {
  strings:
    $key_05c7 = { 56 a8 [2] 72 a6 [2] 59 8a [2] 77 a8 [2] 63 b3 [2] 6c a9 [2] 72 b4 [2] 70 b5 [2] 6b b3 [2] 77 b4 [2] 6b 9b }

  condition:
    any of them
}