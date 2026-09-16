rule TTP_XOR_QUAD_CurrentVersionRun_4656 {
  strings:
    $key_4656 = { 15 39 [2] 31 37 [2] 1a 1b [2] 34 39 [2] 20 22 [2] 2f 38 [2] 31 25 [2] 33 24 [2] 28 22 [2] 34 25 [2] 28 0a }

  condition:
    any of them
}