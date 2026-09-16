rule TTP_XOR_QUAD_CurrentVersionRun_5276 {
  strings:
    $key_5276 = { 01 19 [2] 25 17 [2] 0e 3b [2] 20 19 [2] 34 02 [2] 3b 18 [2] 25 05 [2] 27 04 [2] 3c 02 [2] 20 05 [2] 3c 2a }

  condition:
    any of them
}