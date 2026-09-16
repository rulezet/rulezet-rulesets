rule TTP_XOR_QUAD_CurrentVersionRun_7c73 {
  strings:
    $key_7c73 = { 2f 1c [2] 0b 12 [2] 20 3e [2] 0e 1c [2] 1a 07 [2] 15 1d [2] 0b 00 [2] 09 01 [2] 12 07 [2] 0e 00 [2] 12 2f }

  condition:
    any of them
}