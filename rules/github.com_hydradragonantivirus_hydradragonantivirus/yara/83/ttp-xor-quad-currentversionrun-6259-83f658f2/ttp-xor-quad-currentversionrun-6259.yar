rule TTP_XOR_QUAD_CurrentVersionRun_6259 {
  strings:
    $key_6259 = { 31 36 [2] 15 38 [2] 3e 14 [2] 10 36 [2] 04 2d [2] 0b 37 [2] 15 2a [2] 17 2b [2] 0c 2d [2] 10 2a [2] 0c 05 }

  condition:
    any of them
}