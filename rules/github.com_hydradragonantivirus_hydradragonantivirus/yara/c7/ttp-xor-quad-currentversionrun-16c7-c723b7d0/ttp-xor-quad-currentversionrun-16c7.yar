rule TTP_XOR_QUAD_CurrentVersionRun_16c7 {
  strings:
    $key_16c7 = { 45 a8 [2] 61 a6 [2] 4a 8a [2] 64 a8 [2] 70 b3 [2] 7f a9 [2] 61 b4 [2] 63 b5 [2] 78 b3 [2] 64 b4 [2] 78 9b }

  condition:
    any of them
}