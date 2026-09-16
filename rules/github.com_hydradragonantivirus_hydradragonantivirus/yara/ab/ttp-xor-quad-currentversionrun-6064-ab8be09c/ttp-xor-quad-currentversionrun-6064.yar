rule TTP_XOR_QUAD_CurrentVersionRun_6064 {
  strings:
    $key_6064 = { 33 0b [2] 17 05 [2] 3c 29 [2] 12 0b [2] 06 10 [2] 09 0a [2] 17 17 [2] 15 16 [2] 0e 10 [2] 12 17 [2] 0e 38 }

  condition:
    any of them
}