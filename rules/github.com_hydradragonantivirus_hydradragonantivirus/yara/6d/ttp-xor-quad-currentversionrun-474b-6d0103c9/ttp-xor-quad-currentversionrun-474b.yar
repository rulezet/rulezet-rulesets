rule TTP_XOR_QUAD_CurrentVersionRun_474b {
  strings:
    $key_474b = { 14 24 [2] 30 2a [2] 1b 06 [2] 35 24 [2] 21 3f [2] 2e 25 [2] 30 38 [2] 32 39 [2] 29 3f [2] 35 38 [2] 29 17 }

  condition:
    any of them
}