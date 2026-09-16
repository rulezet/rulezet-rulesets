rule TTP_XOR_QUAD_CurrentVersionRun_6569 {
  strings:
    $key_6569 = { 36 06 [2] 12 08 [2] 39 24 [2] 17 06 [2] 03 1d [2] 0c 07 [2] 12 1a [2] 10 1b [2] 0b 1d [2] 17 1a [2] 0b 35 }

  condition:
    any of them
}