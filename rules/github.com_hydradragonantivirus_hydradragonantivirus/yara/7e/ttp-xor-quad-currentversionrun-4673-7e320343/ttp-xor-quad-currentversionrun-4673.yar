rule TTP_XOR_QUAD_CurrentVersionRun_4673 {
  strings:
    $key_4673 = { 15 1c [2] 31 12 [2] 1a 3e [2] 34 1c [2] 20 07 [2] 2f 1d [2] 31 00 [2] 33 01 [2] 28 07 [2] 34 00 [2] 28 2f }

  condition:
    any of them
}