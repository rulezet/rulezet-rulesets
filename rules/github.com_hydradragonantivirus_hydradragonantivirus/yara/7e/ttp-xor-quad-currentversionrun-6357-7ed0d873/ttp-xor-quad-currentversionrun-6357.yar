rule TTP_XOR_QUAD_CurrentVersionRun_6357 {
  strings:
    $key_6357 = { 30 38 [2] 14 36 [2] 3f 1a [2] 11 38 [2] 05 23 [2] 0a 39 [2] 14 24 [2] 16 25 [2] 0d 23 [2] 11 24 [2] 0d 0b }

  condition:
    any of them
}