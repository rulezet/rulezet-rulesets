rule TTP_XOR_QUAD_CurrentVersionRun_0b73 {
  strings:
    $key_0b73 = { 58 1c [2] 7c 12 [2] 57 3e [2] 79 1c [2] 6d 07 [2] 62 1d [2] 7c 00 [2] 7e 01 [2] 65 07 [2] 79 00 [2] 65 2f }

  condition:
    any of them
}