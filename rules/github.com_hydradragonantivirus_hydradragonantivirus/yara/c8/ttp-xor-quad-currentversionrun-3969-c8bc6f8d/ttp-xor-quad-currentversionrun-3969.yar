rule TTP_XOR_QUAD_CurrentVersionRun_3969 {
  strings:
    $key_3969 = { 6a 06 [2] 4e 08 [2] 65 24 [2] 4b 06 [2] 5f 1d [2] 50 07 [2] 4e 1a [2] 4c 1b [2] 57 1d [2] 4b 1a [2] 57 35 }

  condition:
    any of them
}