rule TTP_XOR_QUAD_CurrentVersionRun_0473 {
  strings:
    $key_0473 = { 57 1c [2] 73 12 [2] 58 3e [2] 76 1c [2] 62 07 [2] 6d 1d [2] 73 00 [2] 71 01 [2] 6a 07 [2] 76 00 [2] 6a 2f }

  condition:
    any of them
}