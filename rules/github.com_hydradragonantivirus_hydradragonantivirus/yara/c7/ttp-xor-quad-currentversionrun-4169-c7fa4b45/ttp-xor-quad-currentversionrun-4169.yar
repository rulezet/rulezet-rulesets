rule TTP_XOR_QUAD_CurrentVersionRun_4169 {
  strings:
    $key_4169 = { 12 06 [2] 36 08 [2] 1d 24 [2] 33 06 [2] 27 1d [2] 28 07 [2] 36 1a [2] 34 1b [2] 2f 1d [2] 33 1a [2] 2f 35 }

  condition:
    any of them
}