rule TTP_XOR_QUAD_CurrentVersionRun_0c73 {
  strings:
    $key_0c73 = { 5f 1c [2] 7b 12 [2] 50 3e [2] 7e 1c [2] 6a 07 [2] 65 1d [2] 7b 00 [2] 79 01 [2] 62 07 [2] 7e 00 [2] 62 2f }

  condition:
    any of them
}