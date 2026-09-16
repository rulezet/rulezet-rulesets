rule TTP_XOR_QUAD_CurrentVersionRun_4b73 {
  strings:
    $key_4b73 = { 18 1c [2] 3c 12 [2] 17 3e [2] 39 1c [2] 2d 07 [2] 22 1d [2] 3c 00 [2] 3e 01 [2] 25 07 [2] 39 00 [2] 25 2f }

  condition:
    any of them
}