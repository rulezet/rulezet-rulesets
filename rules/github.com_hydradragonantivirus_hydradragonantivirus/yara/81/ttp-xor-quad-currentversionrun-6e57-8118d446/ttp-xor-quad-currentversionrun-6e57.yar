rule TTP_XOR_QUAD_CurrentVersionRun_6e57 {
  strings:
    $key_6e57 = { 3d 38 [2] 19 36 [2] 32 1a [2] 1c 38 [2] 08 23 [2] 07 39 [2] 19 24 [2] 1b 25 [2] 00 23 [2] 1c 24 [2] 00 0b }

  condition:
    any of them
}