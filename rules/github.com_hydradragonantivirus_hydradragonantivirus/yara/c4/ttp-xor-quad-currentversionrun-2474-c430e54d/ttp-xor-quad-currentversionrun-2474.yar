rule TTP_XOR_QUAD_CurrentVersionRun_2474 {
  strings:
    $key_2474 = { 77 1b [2] 53 15 [2] 78 39 [2] 56 1b [2] 42 00 [2] 4d 1a [2] 53 07 [2] 51 06 [2] 4a 00 [2] 56 07 [2] 4a 28 }

  condition:
    any of them
}