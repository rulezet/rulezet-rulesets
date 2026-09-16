rule TTP_XOR_QUAD_CurrentVersionRun_6e45 {
  strings:
    $key_6e45 = { 3d 2a [2] 19 24 [2] 32 08 [2] 1c 2a [2] 08 31 [2] 07 2b [2] 19 36 [2] 1b 37 [2] 00 31 [2] 1c 36 [2] 00 19 }

  condition:
    any of them
}