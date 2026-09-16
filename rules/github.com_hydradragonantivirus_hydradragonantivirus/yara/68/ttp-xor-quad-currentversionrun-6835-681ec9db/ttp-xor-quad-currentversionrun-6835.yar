rule TTP_XOR_QUAD_CurrentVersionRun_6835 {
  strings:
    $key_6835 = { 3b 5a [2] 1f 54 [2] 34 78 [2] 1a 5a [2] 0e 41 [2] 01 5b [2] 1f 46 [2] 1d 47 [2] 06 41 [2] 1a 46 [2] 06 69 }

  condition:
    any of them
}