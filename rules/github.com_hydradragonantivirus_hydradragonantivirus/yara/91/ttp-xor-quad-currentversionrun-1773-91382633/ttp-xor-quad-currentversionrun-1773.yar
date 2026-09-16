rule TTP_XOR_QUAD_CurrentVersionRun_1773 {
  strings:
    $key_1773 = { 44 1c [2] 60 12 [2] 4b 3e [2] 65 1c [2] 71 07 [2] 7e 1d [2] 60 00 [2] 62 01 [2] 79 07 [2] 65 00 [2] 79 2f }

  condition:
    any of them
}