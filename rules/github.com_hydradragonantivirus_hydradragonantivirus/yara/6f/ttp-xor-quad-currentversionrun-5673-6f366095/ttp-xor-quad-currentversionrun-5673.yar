rule TTP_XOR_QUAD_CurrentVersionRun_5673 {
  strings:
    $key_5673 = { 05 1c [2] 21 12 [2] 0a 3e [2] 24 1c [2] 30 07 [2] 3f 1d [2] 21 00 [2] 23 01 [2] 38 07 [2] 24 00 [2] 38 2f }

  condition:
    any of them
}