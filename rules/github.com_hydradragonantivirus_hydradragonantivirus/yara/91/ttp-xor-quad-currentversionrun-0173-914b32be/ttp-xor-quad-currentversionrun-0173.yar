rule TTP_XOR_QUAD_CurrentVersionRun_0173 {
  strings:
    $key_0173 = { 52 1c [2] 76 12 [2] 5d 3e [2] 73 1c [2] 67 07 [2] 68 1d [2] 76 00 [2] 74 01 [2] 6f 07 [2] 73 00 [2] 6f 2f }

  condition:
    any of them
}