rule TTP_XOR_QUAD_CurrentVersionRun_2244 {
  strings:
    $key_2244 = { 71 2b [2] 55 25 [2] 7e 09 [2] 50 2b [2] 44 30 [2] 4b 2a [2] 55 37 [2] 57 36 [2] 4c 30 [2] 50 37 [2] 4c 18 }

  condition:
    any of them
}