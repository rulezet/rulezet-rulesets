rule TTP_XOR_QUAD_CurrentVersionRun_2a69 {
  strings:
    $key_2a69 = { 79 06 [2] 5d 08 [2] 76 24 [2] 58 06 [2] 4c 1d [2] 43 07 [2] 5d 1a [2] 5f 1b [2] 44 1d [2] 58 1a [2] 44 35 }

  condition:
    any of them
}