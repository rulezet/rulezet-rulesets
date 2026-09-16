rule TTP_XOR_QUAD_CurrentVersionRun_6e49 {
  strings:
    $key_6e49 = { 3d 26 [2] 19 28 [2] 32 04 [2] 1c 26 [2] 08 3d [2] 07 27 [2] 19 3a [2] 1b 3b [2] 00 3d [2] 1c 3a [2] 00 15 }

  condition:
    any of them
}