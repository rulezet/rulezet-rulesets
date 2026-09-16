rule TTP_XOR_QUAD_CurrentVersionRun_0e73 {
  strings:
    $key_0e73 = { 5d 1c [2] 79 12 [2] 52 3e [2] 7c 1c [2] 68 07 [2] 67 1d [2] 79 00 [2] 7b 01 [2] 60 07 [2] 7c 00 [2] 60 2f }

  condition:
    any of them
}