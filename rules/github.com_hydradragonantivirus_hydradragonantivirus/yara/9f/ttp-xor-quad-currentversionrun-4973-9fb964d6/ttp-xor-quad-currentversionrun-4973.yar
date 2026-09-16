rule TTP_XOR_QUAD_CurrentVersionRun_4973 {
  strings:
    $key_4973 = { 1a 1c [2] 3e 12 [2] 15 3e [2] 3b 1c [2] 2f 07 [2] 20 1d [2] 3e 00 [2] 3c 01 [2] 27 07 [2] 3b 00 [2] 27 2f }

  condition:
    any of them
}