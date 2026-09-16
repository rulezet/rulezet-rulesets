rule TTP_XOR_QUAD_CurrentVersionRun_6844 {
  strings:
    $key_6844 = { 3b 2b [2] 1f 25 [2] 34 09 [2] 1a 2b [2] 0e 30 [2] 01 2a [2] 1f 37 [2] 1d 36 [2] 06 30 [2] 1a 37 [2] 06 18 }

  condition:
    any of them
}