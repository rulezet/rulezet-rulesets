rule TTP_XOR_QUAD_CurrentVersionRun_5666 {
  strings:
    $key_5666 = { 05 09 [2] 21 07 [2] 0a 2b [2] 24 09 [2] 30 12 [2] 3f 08 [2] 21 15 [2] 23 14 [2] 38 12 [2] 24 15 [2] 38 3a }

  condition:
    any of them
}