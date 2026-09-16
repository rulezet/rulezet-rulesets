rule TTP_XOR_QUAD_CurrentVersionRun_5277 {
  strings:
    $key_5277 = { 01 18 [2] 25 16 [2] 0e 3a [2] 20 18 [2] 34 03 [2] 3b 19 [2] 25 04 [2] 27 05 [2] 3c 03 [2] 20 04 [2] 3c 2b }

  condition:
    any of them
}