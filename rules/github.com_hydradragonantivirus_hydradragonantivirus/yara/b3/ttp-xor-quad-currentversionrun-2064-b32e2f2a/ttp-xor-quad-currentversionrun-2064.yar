rule TTP_XOR_QUAD_CurrentVersionRun_2064 {
  strings:
    $key_2064 = { 73 0b [2] 57 05 [2] 7c 29 [2] 52 0b [2] 46 10 [2] 49 0a [2] 57 17 [2] 55 16 [2] 4e 10 [2] 52 17 [2] 4e 38 }

  condition:
    any of them
}