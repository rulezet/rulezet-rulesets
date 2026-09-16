rule TTP_XOR_QUAD_CurrentVersionRun_0357 {
  strings:
    $key_0357 = { 50 38 [2] 74 36 [2] 5f 1a [2] 71 38 [2] 65 23 [2] 6a 39 [2] 74 24 [2] 76 25 [2] 6d 23 [2] 71 24 [2] 6d 0b }

  condition:
    any of them
}