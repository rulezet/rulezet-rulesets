rule TTP_XOR_QUAD_CurrentVersionRun_6973 {
  strings:
    $key_6973 = { 3a 1c [2] 1e 12 [2] 35 3e [2] 1b 1c [2] 0f 07 [2] 00 1d [2] 1e 00 [2] 1c 01 [2] 07 07 [2] 1b 00 [2] 07 2f }

  condition:
    any of them
}