rule TTP_XOR_QUAD_CurrentVersionRun_4d56 {
  strings:
    $key_4d56 = { 1e 39 [2] 3a 37 [2] 11 1b [2] 3f 39 [2] 2b 22 [2] 24 38 [2] 3a 25 [2] 38 24 [2] 23 22 [2] 3f 25 [2] 23 0a }

  condition:
    any of them
}