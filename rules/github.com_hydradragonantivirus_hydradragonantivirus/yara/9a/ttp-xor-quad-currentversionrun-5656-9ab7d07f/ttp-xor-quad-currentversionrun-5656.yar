rule TTP_XOR_QUAD_CurrentVersionRun_5656 {
  strings:
    $key_5656 = { 05 39 [2] 21 37 [2] 0a 1b [2] 24 39 [2] 30 22 [2] 3f 38 [2] 21 25 [2] 23 24 [2] 38 22 [2] 24 25 [2] 38 0a }

  condition:
    any of them
}