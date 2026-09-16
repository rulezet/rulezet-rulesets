rule TTP_XOR_QUAD_CurrentVersionRun_0f57 {
  strings:
    $key_0f57 = { 5c 38 [2] 78 36 [2] 53 1a [2] 7d 38 [2] 69 23 [2] 66 39 [2] 78 24 [2] 7a 25 [2] 61 23 [2] 7d 24 [2] 61 0b }

  condition:
    any of them
}