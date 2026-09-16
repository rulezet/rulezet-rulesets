rule TTP_XOR_QUAD_CurrentVersionRun_7938 {
  strings:
    $key_7938 = { 2a 57 [2] 0e 59 [2] 25 75 [2] 0b 57 [2] 1f 4c [2] 10 56 [2] 0e 4b [2] 0c 4a [2] 17 4c [2] 0b 4b [2] 17 64 }

  condition:
    any of them
}