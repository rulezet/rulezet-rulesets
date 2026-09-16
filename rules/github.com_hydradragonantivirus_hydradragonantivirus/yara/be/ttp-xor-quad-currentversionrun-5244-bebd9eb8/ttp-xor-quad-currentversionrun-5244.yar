rule TTP_XOR_QUAD_CurrentVersionRun_5244 {
  strings:
    $key_5244 = { 01 2b [2] 25 25 [2] 0e 09 [2] 20 2b [2] 34 30 [2] 3b 2a [2] 25 37 [2] 27 36 [2] 3c 30 [2] 20 37 [2] 3c 18 }

  condition:
    any of them
}