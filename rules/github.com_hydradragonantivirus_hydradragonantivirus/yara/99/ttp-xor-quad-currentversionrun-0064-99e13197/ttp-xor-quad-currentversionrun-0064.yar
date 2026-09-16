rule TTP_XOR_QUAD_CurrentVersionRun_0064 {
  strings:
    $key_0064 = { 53 0b [2] 77 05 [2] 5c 29 [2] 72 0b [2] 66 10 [2] 69 0a [2] 77 17 [2] 75 16 [2] 6e 10 [2] 72 17 [2] 6e 38 }

  condition:
    any of them
}