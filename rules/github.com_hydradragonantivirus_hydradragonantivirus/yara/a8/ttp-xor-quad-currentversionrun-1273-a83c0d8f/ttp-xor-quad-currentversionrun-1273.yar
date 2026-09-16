rule TTP_XOR_QUAD_CurrentVersionRun_1273 {
  strings:
    $key_1273 = { 41 1c [2] 65 12 [2] 4e 3e [2] 60 1c [2] 74 07 [2] 7b 1d [2] 65 00 [2] 67 01 [2] 7c 07 [2] 60 00 [2] 7c 2f }

  condition:
    any of them
}