rule TTP_XOR_QUAD_CurrentVersionRun_0467 {
  strings:
    $key_0467 = { 57 08 [2] 73 06 [2] 58 2a [2] 76 08 [2] 62 13 [2] 6d 09 [2] 73 14 [2] 71 15 [2] 6a 13 [2] 76 14 [2] 6a 3b }

  condition:
    any of them
}