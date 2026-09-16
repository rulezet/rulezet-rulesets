rule TTP_XOR_QUAD_CurrentVersionRun_5665 {
  strings:
    $key_5665 = { 05 0a [2] 21 04 [2] 0a 28 [2] 24 0a [2] 30 11 [2] 3f 0b [2] 21 16 [2] 23 17 [2] 38 11 [2] 24 16 [2] 38 39 }

  condition:
    any of them
}