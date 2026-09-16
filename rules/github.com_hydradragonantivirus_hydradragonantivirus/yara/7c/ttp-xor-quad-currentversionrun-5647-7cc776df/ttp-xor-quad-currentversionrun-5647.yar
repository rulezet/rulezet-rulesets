rule TTP_XOR_QUAD_CurrentVersionRun_5647 {
  strings:
    $key_5647 = { 05 28 [2] 21 26 [2] 0a 0a [2] 24 28 [2] 30 33 [2] 3f 29 [2] 21 34 [2] 23 35 [2] 38 33 [2] 24 34 [2] 38 1b }

  condition:
    any of them
}