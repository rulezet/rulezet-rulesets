rule TTP_XOR_QUAD_CurrentVersionRun_6e4b {
  strings:
    $key_6e4b = { 3d 24 [2] 19 2a [2] 32 06 [2] 1c 24 [2] 08 3f [2] 07 25 [2] 19 38 [2] 1b 39 [2] 00 3f [2] 1c 38 [2] 00 17 }

  condition:
    any of them
}