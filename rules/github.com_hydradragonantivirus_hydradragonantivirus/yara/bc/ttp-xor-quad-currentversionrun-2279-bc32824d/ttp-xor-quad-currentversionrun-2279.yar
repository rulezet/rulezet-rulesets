rule TTP_XOR_QUAD_CurrentVersionRun_2279 {
  strings:
    $key_2279 = { 71 16 [2] 55 18 [2] 7e 34 [2] 50 16 [2] 44 0d [2] 4b 17 [2] 55 0a [2] 57 0b [2] 4c 0d [2] 50 0a [2] 4c 25 }

  condition:
    any of them
}