rule TTP_XOR_QUAD_CurrentVersionRun_4e56 {
  strings:
    $key_4e56 = { 1d 39 [2] 39 37 [2] 12 1b [2] 3c 39 [2] 28 22 [2] 27 38 [2] 39 25 [2] 3b 24 [2] 20 22 [2] 3c 25 [2] 20 0a }

  condition:
    any of them
}