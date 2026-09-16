rule TTP_XOR_QUAD_CurrentVersionRun_6e74 {
  strings:
    $key_6e74 = { 3d 1b [2] 19 15 [2] 32 39 [2] 1c 1b [2] 08 00 [2] 07 1a [2] 19 07 [2] 1b 06 [2] 00 00 [2] 1c 07 [2] 00 28 }

  condition:
    any of them
}