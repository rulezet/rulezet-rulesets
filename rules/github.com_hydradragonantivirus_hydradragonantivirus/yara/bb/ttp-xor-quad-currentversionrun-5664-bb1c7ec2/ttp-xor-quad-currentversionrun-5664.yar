rule TTP_XOR_QUAD_CurrentVersionRun_5664 {
  strings:
    $key_5664 = { 05 0b [2] 21 05 [2] 0a 29 [2] 24 0b [2] 30 10 [2] 3f 0a [2] 21 17 [2] 23 16 [2] 38 10 [2] 24 17 [2] 38 38 }

  condition:
    any of them
}