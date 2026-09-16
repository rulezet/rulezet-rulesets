rule TTP_XOR_QUAD_CurrentVersionRun_6d73 {
  strings:
    $key_6d73 = { 3e 1c [2] 1a 12 [2] 31 3e [2] 1f 1c [2] 0b 07 [2] 04 1d [2] 1a 00 [2] 18 01 [2] 03 07 [2] 1f 00 [2] 03 2f }

  condition:
    any of them
}