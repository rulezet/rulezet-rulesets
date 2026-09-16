rule TTP_XOR_QUAD_CurrentVersionRun_f064 {
  strings:
    $key_f064 = { a3 0b [2] 87 05 [2] ac 29 [2] 82 0b [2] 96 10 [2] 99 0a [2] 87 17 [2] 85 16 [2] 9e 10 [2] 82 17 [2] 9e 38 }

  condition:
    any of them
}