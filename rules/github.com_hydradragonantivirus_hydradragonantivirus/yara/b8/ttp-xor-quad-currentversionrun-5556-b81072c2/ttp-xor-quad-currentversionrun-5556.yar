rule TTP_XOR_QUAD_CurrentVersionRun_5556 {
  strings:
    $key_5556 = { 06 39 [2] 22 37 [2] 09 1b [2] 27 39 [2] 33 22 [2] 3c 38 [2] 22 25 [2] 20 24 [2] 3b 22 [2] 27 25 [2] 3b 0a }

  condition:
    any of them
}