rule TTP_XOR_QUAD_CurrentVersionRun_5269 {
  strings:
    $key_5269 = { 01 06 [2] 25 08 [2] 0e 24 [2] 20 06 [2] 34 1d [2] 3b 07 [2] 25 1a [2] 27 1b [2] 3c 1d [2] 20 1a [2] 3c 35 }

  condition:
    any of them
}