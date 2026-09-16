rule TTP_XOR_QUAD_CurrentVersionRun_5873 {
  strings:
    $key_5873 = { 0b 1c [2] 2f 12 [2] 04 3e [2] 2a 1c [2] 3e 07 [2] 31 1d [2] 2f 00 [2] 2d 01 [2] 36 07 [2] 2a 00 [2] 36 2f }

  condition:
    any of them
}