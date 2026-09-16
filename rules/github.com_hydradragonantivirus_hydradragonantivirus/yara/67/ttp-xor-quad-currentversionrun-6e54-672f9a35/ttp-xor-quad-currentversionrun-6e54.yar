rule TTP_XOR_QUAD_CurrentVersionRun_6e54 {
  strings:
    $key_6e54 = { 3d 3b [2] 19 35 [2] 32 19 [2] 1c 3b [2] 08 20 [2] 07 3a [2] 19 27 [2] 1b 26 [2] 00 20 [2] 1c 27 [2] 00 08 }

  condition:
    any of them
}