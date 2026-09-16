rule TTP_XOR_QUAD_CurrentVersionRun_1367 {
  strings:
    $key_1367 = { 40 08 [2] 64 06 [2] 4f 2a [2] 61 08 [2] 75 13 [2] 7a 09 [2] 64 14 [2] 66 15 [2] 7d 13 [2] 61 14 [2] 7d 3b }

  condition:
    any of them
}