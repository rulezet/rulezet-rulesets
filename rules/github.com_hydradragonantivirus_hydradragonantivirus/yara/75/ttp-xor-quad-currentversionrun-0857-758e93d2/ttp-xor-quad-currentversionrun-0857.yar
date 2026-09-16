rule TTP_XOR_QUAD_CurrentVersionRun_0857 {
  strings:
    $key_0857 = { 5b 38 [2] 7f 36 [2] 54 1a [2] 7a 38 [2] 6e 23 [2] 61 39 [2] 7f 24 [2] 7d 25 [2] 66 23 [2] 7a 24 [2] 66 0b }

  condition:
    any of them
}