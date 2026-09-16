rule TTP_XOR_QUAD_CurrentVersionRun_1573 {
  strings:
    $key_1573 = { 46 1c [2] 62 12 [2] 49 3e [2] 67 1c [2] 73 07 [2] 7c 1d [2] 62 00 [2] 60 01 [2] 7b 07 [2] 67 00 [2] 7b 2f }

  condition:
    any of them
}