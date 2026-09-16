rule TTP_XOR_QUAD_CurrentVersionRun_4c69 {
  strings:
    $key_4c69 = { 1f 06 [2] 3b 08 [2] 10 24 [2] 3e 06 [2] 2a 1d [2] 25 07 [2] 3b 1a [2] 39 1b [2] 22 1d [2] 3e 1a [2] 22 35 }

  condition:
    any of them
}