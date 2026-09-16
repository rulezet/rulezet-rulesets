rule TTP_XOR_QUAD_CurrentVersionRun_2a64 {
  strings:
    $key_2a64 = { 79 0b [2] 5d 05 [2] 76 29 [2] 58 0b [2] 4c 10 [2] 43 0a [2] 5d 17 [2] 5f 16 [2] 44 10 [2] 58 17 [2] 44 38 }

  condition:
    any of them
}