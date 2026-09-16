rule TTP_XOR_QUAD_CurrentVersionRun_6e79 {
  strings:
    $key_6e79 = { 3d 16 [2] 19 18 [2] 32 34 [2] 1c 16 [2] 08 0d [2] 07 17 [2] 19 0a [2] 1b 0b [2] 00 0d [2] 1c 0a [2] 00 25 }

  condition:
    any of them
}