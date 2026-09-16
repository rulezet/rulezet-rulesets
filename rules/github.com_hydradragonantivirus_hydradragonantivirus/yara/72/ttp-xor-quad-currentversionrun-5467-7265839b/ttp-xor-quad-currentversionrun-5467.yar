rule TTP_XOR_QUAD_CurrentVersionRun_5467 {
  strings:
    $key_5467 = { 07 08 [2] 23 06 [2] 08 2a [2] 26 08 [2] 32 13 [2] 3d 09 [2] 23 14 [2] 21 15 [2] 3a 13 [2] 26 14 [2] 3a 3b }

  condition:
    any of them
}