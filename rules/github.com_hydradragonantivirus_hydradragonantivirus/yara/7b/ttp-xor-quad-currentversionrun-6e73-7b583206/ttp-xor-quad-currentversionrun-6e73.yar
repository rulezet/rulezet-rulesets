rule TTP_XOR_QUAD_CurrentVersionRun_6e73 {
  strings:
    $key_6e73 = { 3d 1c [2] 19 12 [2] 32 3e [2] 1c 1c [2] 08 07 [2] 07 1d [2] 19 00 [2] 1b 01 [2] 00 07 [2] 1c 00 [2] 00 2f }

  condition:
    any of them
}