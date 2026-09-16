rule TTP_XOR_QUAD_CurrentVersionRun_0569 {
  strings:
    $key_0569 = { 56 06 [2] 72 08 [2] 59 24 [2] 77 06 [2] 63 1d [2] 6c 07 [2] 72 1a [2] 70 1b [2] 6b 1d [2] 77 1a [2] 6b 35 }

  condition:
    any of them
}