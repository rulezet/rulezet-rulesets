rule TTP_XOR_QUAD_CurrentVersionRun_1756 {
  strings:
    $key_1756 = { 44 39 [2] 60 37 [2] 4b 1b [2] 65 39 [2] 71 22 [2] 7e 38 [2] 60 25 [2] 62 24 [2] 79 22 [2] 65 25 [2] 79 0a }

  condition:
    any of them
}