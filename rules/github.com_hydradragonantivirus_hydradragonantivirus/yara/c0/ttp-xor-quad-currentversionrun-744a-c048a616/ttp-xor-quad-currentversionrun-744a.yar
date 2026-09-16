rule TTP_XOR_QUAD_CurrentVersionRun_744a {
  strings:
    $key_744a = { 27 25 [2] 03 2b [2] 28 07 [2] 06 25 [2] 12 3e [2] 1d 24 [2] 03 39 [2] 01 38 [2] 1a 3e [2] 06 39 [2] 1a 16 }

  condition:
    any of them
}