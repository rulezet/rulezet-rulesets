rule TTP_XOR_QUAD_CurrentVersionRun_5655 {
  strings:
    $key_5655 = { 05 3a [2] 21 34 [2] 0a 18 [2] 24 3a [2] 30 21 [2] 3f 3b [2] 21 26 [2] 23 27 [2] 38 21 [2] 24 26 [2] 38 09 }

  condition:
    any of them
}