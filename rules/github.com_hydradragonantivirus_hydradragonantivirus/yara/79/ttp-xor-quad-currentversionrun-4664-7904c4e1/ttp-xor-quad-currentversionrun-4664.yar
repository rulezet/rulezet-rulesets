rule TTP_XOR_QUAD_CurrentVersionRun_4664 {
  strings:
    $key_4664 = { 15 0b [2] 31 05 [2] 1a 29 [2] 34 0b [2] 20 10 [2] 2f 0a [2] 31 17 [2] 33 16 [2] 28 10 [2] 34 17 [2] 28 38 }

  condition:
    any of them
}