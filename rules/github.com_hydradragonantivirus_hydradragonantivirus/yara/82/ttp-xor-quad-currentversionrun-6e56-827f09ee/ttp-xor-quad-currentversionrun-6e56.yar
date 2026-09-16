rule TTP_XOR_QUAD_CurrentVersionRun_6e56 {
  strings:
    $key_6e56 = { 3d 39 [2] 19 37 [2] 32 1b [2] 1c 39 [2] 08 22 [2] 07 38 [2] 19 25 [2] 1b 24 [2] 00 22 [2] 1c 25 [2] 00 0a }

  condition:
    any of them
}