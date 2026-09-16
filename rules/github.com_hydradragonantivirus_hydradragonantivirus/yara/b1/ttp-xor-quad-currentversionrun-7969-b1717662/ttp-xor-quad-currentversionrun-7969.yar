rule TTP_XOR_QUAD_CurrentVersionRun_7969 {
  strings:
    $key_7969 = { 2a 06 [2] 0e 08 [2] 25 24 [2] 0b 06 [2] 1f 1d [2] 10 07 [2] 0e 1a [2] 0c 1b [2] 17 1d [2] 0b 1a [2] 17 35 }

  condition:
    any of them
}