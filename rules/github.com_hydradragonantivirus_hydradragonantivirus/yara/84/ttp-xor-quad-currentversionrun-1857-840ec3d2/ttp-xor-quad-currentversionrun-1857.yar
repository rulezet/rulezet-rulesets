rule TTP_XOR_QUAD_CurrentVersionRun_1857 {
  strings:
    $key_1857 = { 4b 38 [2] 6f 36 [2] 44 1a [2] 6a 38 [2] 7e 23 [2] 71 39 [2] 6f 24 [2] 6d 25 [2] 76 23 [2] 6a 24 [2] 76 0b }

  condition:
    any of them
}