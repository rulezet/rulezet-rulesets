rule TTP_XOR_QUAD_CurrentVersionRun_2769 {
  strings:
    $key_2769 = { 74 06 [2] 50 08 [2] 7b 24 [2] 55 06 [2] 41 1d [2] 4e 07 [2] 50 1a [2] 52 1b [2] 49 1d [2] 55 1a [2] 49 35 }

  condition:
    any of them
}