rule TTP_XOR_QUAD_CurrentVersionRun_2577 {
  strings:
    $key_2577 = { 76 18 [2] 52 16 [2] 79 3a [2] 57 18 [2] 43 03 [2] 4c 19 [2] 52 04 [2] 50 05 [2] 4b 03 [2] 57 04 [2] 4b 2b }

  condition:
    any of them
}