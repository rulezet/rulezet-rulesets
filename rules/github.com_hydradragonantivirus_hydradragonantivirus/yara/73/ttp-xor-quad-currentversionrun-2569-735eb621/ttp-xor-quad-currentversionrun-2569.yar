rule TTP_XOR_QUAD_CurrentVersionRun_2569 {
  strings:
    $key_2569 = { 76 06 [2] 52 08 [2] 79 24 [2] 57 06 [2] 43 1d [2] 4c 07 [2] 52 1a [2] 50 1b [2] 4b 1d [2] 57 1a [2] 4b 35 }

  condition:
    any of them
}