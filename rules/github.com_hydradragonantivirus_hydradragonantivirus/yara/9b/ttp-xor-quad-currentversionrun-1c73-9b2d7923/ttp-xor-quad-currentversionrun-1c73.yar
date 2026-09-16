rule TTP_XOR_QUAD_CurrentVersionRun_1c73 {
  strings:
    $key_1c73 = { 4f 1c [2] 6b 12 [2] 40 3e [2] 6e 1c [2] 7a 07 [2] 75 1d [2] 6b 00 [2] 69 01 [2] 72 07 [2] 6e 00 [2] 72 2f }

  condition:
    any of them
}