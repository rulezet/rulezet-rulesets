rule TTP_XOR_QUAD_CurrentVersionRun_6073 {
  strings:
    $key_6073 = { 33 1c [2] 17 12 [2] 3c 3e [2] 12 1c [2] 06 07 [2] 09 1d [2] 17 00 [2] 15 01 [2] 0e 07 [2] 12 00 [2] 0e 2f }

  condition:
    any of them
}