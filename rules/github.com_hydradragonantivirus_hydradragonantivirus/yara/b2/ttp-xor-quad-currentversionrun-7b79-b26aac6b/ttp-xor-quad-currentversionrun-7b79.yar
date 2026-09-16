rule TTP_XOR_QUAD_CurrentVersionRun_7b79 {
  strings:
    $key_7b79 = { 28 16 [2] 0c 18 [2] 27 34 [2] 09 16 [2] 1d 0d [2] 12 17 [2] 0c 0a [2] 0e 0b [2] 15 0d [2] 09 0a [2] 15 25 }

  condition:
    any of them
}