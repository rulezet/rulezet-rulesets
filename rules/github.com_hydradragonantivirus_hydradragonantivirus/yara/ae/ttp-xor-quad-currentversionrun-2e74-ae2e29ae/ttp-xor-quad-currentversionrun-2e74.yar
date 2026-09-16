rule TTP_XOR_QUAD_CurrentVersionRun_2e74 {
  strings:
    $key_2e74 = { 7d 1b [2] 59 15 [2] 72 39 [2] 5c 1b [2] 48 00 [2] 47 1a [2] 59 07 [2] 5b 06 [2] 40 00 [2] 5c 07 [2] 40 28 }

  condition:
    any of them
}