rule TTP_XOR_QUAD_CurrentVersionRun_3269 {
  strings:
    $key_3269 = { 61 06 [2] 45 08 [2] 6e 24 [2] 40 06 [2] 54 1d [2] 5b 07 [2] 45 1a [2] 47 1b [2] 5c 1d [2] 40 1a [2] 5c 35 }

  condition:
    any of them
}