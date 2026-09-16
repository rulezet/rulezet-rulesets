rule TTP_XOR_QUAD_CurrentVersionRun_1e56 {
  strings:
    $key_1e56 = { 4d 39 [2] 69 37 [2] 42 1b [2] 6c 39 [2] 78 22 [2] 77 38 [2] 69 25 [2] 6b 24 [2] 70 22 [2] 6c 25 [2] 70 0a }

  condition:
    any of them
}