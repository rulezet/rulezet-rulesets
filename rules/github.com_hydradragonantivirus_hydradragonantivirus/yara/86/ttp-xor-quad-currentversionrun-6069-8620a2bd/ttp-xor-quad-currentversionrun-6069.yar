rule TTP_XOR_QUAD_CurrentVersionRun_6069 {
  strings:
    $key_6069 = { 33 06 [2] 17 08 [2] 3c 24 [2] 12 06 [2] 06 1d [2] 09 07 [2] 17 1a [2] 15 1b [2] 0e 1d [2] 12 1a [2] 0e 35 }

  condition:
    any of them
}