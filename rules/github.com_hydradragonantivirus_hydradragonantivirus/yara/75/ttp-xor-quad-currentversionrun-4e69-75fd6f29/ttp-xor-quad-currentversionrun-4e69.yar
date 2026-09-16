rule TTP_XOR_QUAD_CurrentVersionRun_4e69 {
  strings:
    $key_4e69 = { 1d 06 [2] 39 08 [2] 12 24 [2] 3c 06 [2] 28 1d [2] 27 07 [2] 39 1a [2] 3b 1b [2] 20 1d [2] 3c 1a [2] 20 35 }

  condition:
    any of them
}