rule TTP_XOR_QUAD_CurrentVersionRun_7957 {
  strings:
    $key_7957 = { 2a 38 [2] 0e 36 [2] 25 1a [2] 0b 38 [2] 1f 23 [2] 10 39 [2] 0e 24 [2] 0c 25 [2] 17 23 [2] 0b 24 [2] 17 0b }

  condition:
    any of them
}