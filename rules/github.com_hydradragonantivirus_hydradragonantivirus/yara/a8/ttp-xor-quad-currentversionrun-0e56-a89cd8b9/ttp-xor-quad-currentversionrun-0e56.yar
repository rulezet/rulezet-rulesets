rule TTP_XOR_QUAD_CurrentVersionRun_0e56 {
  strings:
    $key_0e56 = { 5d 39 [2] 79 37 [2] 52 1b [2] 7c 39 [2] 68 22 [2] 67 38 [2] 79 25 [2] 7b 24 [2] 60 22 [2] 7c 25 [2] 60 0a }

  condition:
    any of them
}