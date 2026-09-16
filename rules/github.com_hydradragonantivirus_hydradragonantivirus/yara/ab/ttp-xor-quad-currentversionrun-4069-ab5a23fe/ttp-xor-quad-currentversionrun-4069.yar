rule TTP_XOR_QUAD_CurrentVersionRun_4069 {
  strings:
    $key_4069 = { 13 06 [2] 37 08 [2] 1c 24 [2] 32 06 [2] 26 1d [2] 29 07 [2] 37 1a [2] 35 1b [2] 2e 1d [2] 32 1a [2] 2e 35 }

  condition:
    any of them
}