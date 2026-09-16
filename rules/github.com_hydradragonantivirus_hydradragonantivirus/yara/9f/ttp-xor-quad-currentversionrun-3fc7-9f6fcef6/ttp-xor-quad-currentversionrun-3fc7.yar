rule TTP_XOR_QUAD_CurrentVersionRun_3fc7 {
  strings:
    $key_3fc7 = { 6c a8 [2] 48 a6 [2] 63 8a [2] 4d a8 [2] 59 b3 [2] 56 a9 [2] 48 b4 [2] 4a b5 [2] 51 b3 [2] 4d b4 [2] 51 9b }

  condition:
    any of them
}