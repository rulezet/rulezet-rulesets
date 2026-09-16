rule TTP_XOR_QUAD_CurrentVersionRun_5564 {
  strings:
    $key_5564 = { 06 0b [2] 22 05 [2] 09 29 [2] 27 0b [2] 33 10 [2] 3c 0a [2] 22 17 [2] 20 16 [2] 3b 10 [2] 27 17 [2] 3b 38 }

  condition:
    any of them
}