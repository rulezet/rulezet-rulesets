rule TTP_XOR_QUAD_CurrentVersionRun_2273 {
  strings:
    $key_2273 = { 71 1c [2] 55 12 [2] 7e 3e [2] 50 1c [2] 44 07 [2] 4b 1d [2] 55 00 [2] 57 01 [2] 4c 07 [2] 50 00 [2] 4c 2f }

  condition:
    any of them
}