rule TTP_XOR_QUAD_CurrentVersionRun_3367 {
  strings:
    $key_3367 = { 60 08 [2] 44 06 [2] 6f 2a [2] 41 08 [2] 55 13 [2] 5a 09 [2] 44 14 [2] 46 15 [2] 5d 13 [2] 41 14 [2] 5d 3b }

  condition:
    any of them
}