rule TTP_XOR_QUAD_CurrentVersionRun_5644 {
  strings:
    $key_5644 = { 05 2b [2] 21 25 [2] 0a 09 [2] 24 2b [2] 30 30 [2] 3f 2a [2] 21 37 [2] 23 36 [2] 38 30 [2] 24 37 [2] 38 18 }

  condition:
    any of them
}