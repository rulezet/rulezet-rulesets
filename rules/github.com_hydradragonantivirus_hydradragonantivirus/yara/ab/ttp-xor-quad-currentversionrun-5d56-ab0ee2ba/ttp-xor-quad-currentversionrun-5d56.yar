rule TTP_XOR_QUAD_CurrentVersionRun_5d56 {
  strings:
    $key_5d56 = { 0e 39 [2] 2a 37 [2] 01 1b [2] 2f 39 [2] 3b 22 [2] 34 38 [2] 2a 25 [2] 28 24 [2] 33 22 [2] 2f 25 [2] 33 0a }

  condition:
    any of them
}