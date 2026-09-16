rule TTP_XOR_QUAD_CurrentVersionRun_2f69 {
  strings:
    $key_2f69 = { 7c 06 [2] 58 08 [2] 73 24 [2] 5d 06 [2] 49 1d [2] 46 07 [2] 58 1a [2] 5a 1b [2] 41 1d [2] 5d 1a [2] 41 35 }

  condition:
    any of them
}