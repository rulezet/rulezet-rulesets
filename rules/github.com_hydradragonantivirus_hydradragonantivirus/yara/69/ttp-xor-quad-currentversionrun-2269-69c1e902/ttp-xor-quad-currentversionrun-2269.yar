rule TTP_XOR_QUAD_CurrentVersionRun_2269 {
  strings:
    $key_2269 = { 71 06 [2] 55 08 [2] 7e 24 [2] 50 06 [2] 44 1d [2] 4b 07 [2] 55 1a [2] 57 1b [2] 4c 1d [2] 50 1a [2] 4c 35 }

  condition:
    any of them
}