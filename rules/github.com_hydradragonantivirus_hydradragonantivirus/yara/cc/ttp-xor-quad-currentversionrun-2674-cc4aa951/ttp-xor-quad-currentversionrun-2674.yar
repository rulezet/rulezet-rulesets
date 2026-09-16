rule TTP_XOR_QUAD_CurrentVersionRun_2674 {
  strings:
    $key_2674 = { 75 1b [2] 51 15 [2] 7a 39 [2] 54 1b [2] 40 00 [2] 4f 1a [2] 51 07 [2] 53 06 [2] 48 00 [2] 54 07 [2] 48 28 }

  condition:
    any of them
}