rule TTP_XOR_QUAD_CurrentVersionRun_2e75 {
  strings:
    $key_2e75 = { 7d 1a [2] 59 14 [2] 72 38 [2] 5c 1a [2] 48 01 [2] 47 1b [2] 59 06 [2] 5b 07 [2] 40 01 [2] 5c 06 [2] 40 29 }

  condition:
    any of them
}