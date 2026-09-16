rule TTP_XOR_QUAD_CurrentVersionRun_6879 {
  strings:
    $key_6879 = { 3b 16 [2] 1f 18 [2] 34 34 [2] 1a 16 [2] 0e 0d [2] 01 17 [2] 1f 0a [2] 1d 0b [2] 06 0d [2] 1a 0a [2] 06 25 }

  condition:
    any of them
}