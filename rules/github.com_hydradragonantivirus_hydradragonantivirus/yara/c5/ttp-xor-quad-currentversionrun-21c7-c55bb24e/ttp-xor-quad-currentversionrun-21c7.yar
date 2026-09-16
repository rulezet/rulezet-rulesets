rule TTP_XOR_QUAD_CurrentVersionRun_21c7 {
  strings:
    $key_21c7 = { 72 a8 [2] 56 a6 [2] 7d 8a [2] 53 a8 [2] 47 b3 [2] 48 a9 [2] 56 b4 [2] 54 b5 [2] 4f b3 [2] 53 b4 [2] 4f 9b }

  condition:
    any of them
}