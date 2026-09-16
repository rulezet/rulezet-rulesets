rule TTP_XOR_QUAD_CurrentVersionRun_4e74 {
  strings:
    $key_4e74 = { 1d 1b [2] 39 15 [2] 12 39 [2] 3c 1b [2] 28 00 [2] 27 1a [2] 39 07 [2] 3b 06 [2] 20 00 [2] 3c 07 [2] 20 28 }

  condition:
    any of them
}