rule TTP_XOR_QUAD_CurrentVersionRun_5f69 {
  strings:
    $key_5f69 = { 0c 06 [2] 28 08 [2] 03 24 [2] 2d 06 [2] 39 1d [2] 36 07 [2] 28 1a [2] 2a 1b [2] 31 1d [2] 2d 1a [2] 31 35 }

  condition:
    any of them
}