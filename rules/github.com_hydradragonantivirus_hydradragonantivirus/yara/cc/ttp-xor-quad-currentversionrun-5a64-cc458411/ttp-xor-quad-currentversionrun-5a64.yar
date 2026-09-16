rule TTP_XOR_QUAD_CurrentVersionRun_5a64 {
  strings:
    $key_5a64 = { 09 0b [2] 2d 05 [2] 06 29 [2] 28 0b [2] 3c 10 [2] 33 0a [2] 2d 17 [2] 2f 16 [2] 34 10 [2] 28 17 [2] 34 38 }

  condition:
    any of them
}