rule TTP_XOR_QUAD_CurrentVersionRun_3173 {
  strings:
    $key_3173 = { 62 1c [2] 46 12 [2] 6d 3e [2] 43 1c [2] 57 07 [2] 58 1d [2] 46 00 [2] 44 01 [2] 5f 07 [2] 43 00 [2] 5f 2f }

  condition:
    any of them
}