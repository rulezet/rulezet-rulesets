rule TTP_XOR_QUAD_CurrentVersionRun_21c6 {
  strings:
    $key_21c6 = { 72 a9 [2] 56 a7 [2] 7d 8b [2] 53 a9 [2] 47 b2 [2] 48 a8 [2] 56 b5 [2] 54 b4 [2] 4f b2 [2] 53 b5 [2] 4f 9a }

  condition:
    any of them
}