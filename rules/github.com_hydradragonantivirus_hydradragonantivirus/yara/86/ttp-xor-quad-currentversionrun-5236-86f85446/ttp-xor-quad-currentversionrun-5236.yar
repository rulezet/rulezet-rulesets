rule TTP_XOR_QUAD_CurrentVersionRun_5236 {
  strings:
    $key_5236 = { 01 59 [2] 25 57 [2] 0e 7b [2] 20 59 [2] 34 42 [2] 3b 58 [2] 25 45 [2] 27 44 [2] 3c 42 [2] 20 45 [2] 3c 6a }

  condition:
    any of them
}