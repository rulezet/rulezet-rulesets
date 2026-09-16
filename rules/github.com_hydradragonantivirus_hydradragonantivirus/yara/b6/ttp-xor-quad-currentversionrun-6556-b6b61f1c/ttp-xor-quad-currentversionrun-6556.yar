rule TTP_XOR_QUAD_CurrentVersionRun_6556 {
  strings:
    $key_6556 = { 36 39 [2] 12 37 [2] 39 1b [2] 17 39 [2] 03 22 [2] 0c 38 [2] 12 25 [2] 10 24 [2] 0b 22 [2] 17 25 [2] 0b 0a }

  condition:
    any of them
}