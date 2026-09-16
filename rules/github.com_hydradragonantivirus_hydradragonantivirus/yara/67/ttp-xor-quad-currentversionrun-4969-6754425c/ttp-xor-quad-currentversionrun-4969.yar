rule TTP_XOR_QUAD_CurrentVersionRun_4969 {
  strings:
    $key_4969 = { 1a 06 [2] 3e 08 [2] 15 24 [2] 3b 06 [2] 2f 1d [2] 20 07 [2] 3e 1a [2] 3c 1b [2] 27 1d [2] 3b 1a [2] 27 35 }

  condition:
    any of them
}