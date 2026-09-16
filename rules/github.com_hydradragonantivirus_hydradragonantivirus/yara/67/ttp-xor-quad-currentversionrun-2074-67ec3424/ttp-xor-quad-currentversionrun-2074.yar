rule TTP_XOR_QUAD_CurrentVersionRun_2074 {
  strings:
    $key_2074 = { 73 1b [2] 57 15 [2] 7c 39 [2] 52 1b [2] 46 00 [2] 49 1a [2] 57 07 [2] 55 06 [2] 4e 00 [2] 52 07 [2] 4e 28 }

  condition:
    any of them
}