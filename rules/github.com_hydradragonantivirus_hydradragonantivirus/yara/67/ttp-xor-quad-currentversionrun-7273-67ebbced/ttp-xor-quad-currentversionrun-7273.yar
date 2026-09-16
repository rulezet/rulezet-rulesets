rule TTP_XOR_QUAD_CurrentVersionRun_7273 {
  strings:
    $key_7273 = { 21 1c [2] 05 12 [2] 2e 3e [2] 00 1c [2] 14 07 [2] 1b 1d [2] 05 00 [2] 07 01 [2] 1c 07 [2] 00 00 [2] 1c 2f }

  condition:
    any of them
}