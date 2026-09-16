rule TTP_XOR_QUAD_CurrentVersionRun_1b73 {
  strings:
    $key_1b73 = { 48 1c [2] 6c 12 [2] 47 3e [2] 69 1c [2] 7d 07 [2] 72 1d [2] 6c 00 [2] 6e 01 [2] 75 07 [2] 69 00 [2] 75 2f }

  condition:
    any of them
}