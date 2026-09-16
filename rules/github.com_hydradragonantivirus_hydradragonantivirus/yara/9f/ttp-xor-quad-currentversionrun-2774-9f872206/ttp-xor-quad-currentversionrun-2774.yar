rule TTP_XOR_QUAD_CurrentVersionRun_2774 {
  strings:
    $key_2774 = { 74 1b [2] 50 15 [2] 7b 39 [2] 55 1b [2] 41 00 [2] 4e 1a [2] 50 07 [2] 52 06 [2] 49 00 [2] 55 07 [2] 49 28 }

  condition:
    any of them
}