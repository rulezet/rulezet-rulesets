rule TTP_XOR_QUAD_CurrentVersionRun_2469 {
  strings:
    $key_2469 = { 77 06 [2] 53 08 [2] 78 24 [2] 56 06 [2] 42 1d [2] 4d 07 [2] 53 1a [2] 51 1b [2] 4a 1d [2] 56 1a [2] 4a 35 }

  condition:
    any of them
}