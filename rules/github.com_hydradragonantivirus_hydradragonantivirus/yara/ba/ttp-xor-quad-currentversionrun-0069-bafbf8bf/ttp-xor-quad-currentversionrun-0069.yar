rule TTP_XOR_QUAD_CurrentVersionRun_0069 {
  strings:
    $key_0069 = { 53 06 [2] 77 08 [2] 5c 24 [2] 72 06 [2] 66 1d [2] 69 07 [2] 77 1a [2] 75 1b [2] 6e 1d [2] 72 1a [2] 6e 35 }

  condition:
    any of them
}