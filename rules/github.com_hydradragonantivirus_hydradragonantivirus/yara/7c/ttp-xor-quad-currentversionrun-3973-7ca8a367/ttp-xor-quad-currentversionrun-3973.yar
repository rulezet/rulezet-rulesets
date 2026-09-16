rule TTP_XOR_QUAD_CurrentVersionRun_3973 {
  strings:
    $key_3973 = { 6a 1c [2] 4e 12 [2] 65 3e [2] 4b 1c [2] 5f 07 [2] 50 1d [2] 4e 00 [2] 4c 01 [2] 57 07 [2] 4b 00 [2] 57 2f }

  condition:
    any of them
}