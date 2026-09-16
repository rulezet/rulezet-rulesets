rule TTP_XOR_QUAD_CurrentVersionRun_1c56 {
  strings:
    $key_1c56 = { 4f 39 [2] 6b 37 [2] 40 1b [2] 6e 39 [2] 7a 22 [2] 75 38 [2] 6b 25 [2] 69 24 [2] 72 22 [2] 6e 25 [2] 72 0a }

  condition:
    any of them
}