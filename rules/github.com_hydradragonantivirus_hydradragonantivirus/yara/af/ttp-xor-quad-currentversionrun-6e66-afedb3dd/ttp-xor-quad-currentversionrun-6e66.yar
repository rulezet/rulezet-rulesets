rule TTP_XOR_QUAD_CurrentVersionRun_6e66 {
  strings:
    $key_6e66 = { 3d 09 [2] 19 07 [2] 32 2b [2] 1c 09 [2] 08 12 [2] 07 08 [2] 19 15 [2] 1b 14 [2] 00 12 [2] 1c 15 [2] 00 3a }

  condition:
    any of them
}