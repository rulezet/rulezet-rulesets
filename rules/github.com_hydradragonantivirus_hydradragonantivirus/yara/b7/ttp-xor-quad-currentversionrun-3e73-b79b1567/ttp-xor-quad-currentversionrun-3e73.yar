rule TTP_XOR_QUAD_CurrentVersionRun_3e73 {
  strings:
    $key_3e73 = { 6d 1c [2] 49 12 [2] 62 3e [2] 4c 1c [2] 58 07 [2] 57 1d [2] 49 00 [2] 4b 01 [2] 50 07 [2] 4c 00 [2] 50 2f }

  condition:
    any of them
}