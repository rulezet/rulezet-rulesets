rule TTP_XOR_QUAD_CurrentVersionRun_6e59 {
  strings:
    $key_6e59 = { 3d 36 [2] 19 38 [2] 32 14 [2] 1c 36 [2] 08 2d [2] 07 37 [2] 19 2a [2] 1b 2b [2] 00 2d [2] 1c 2a [2] 00 05 }

  condition:
    any of them
}