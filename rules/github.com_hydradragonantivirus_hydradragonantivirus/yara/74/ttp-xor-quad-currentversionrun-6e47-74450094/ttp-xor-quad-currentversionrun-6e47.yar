rule TTP_XOR_QUAD_CurrentVersionRun_6e47 {
  strings:
    $key_6e47 = { 3d 28 [2] 19 26 [2] 32 0a [2] 1c 28 [2] 08 33 [2] 07 29 [2] 19 34 [2] 1b 35 [2] 00 33 [2] 1c 34 [2] 00 1b }

  condition:
    any of them
}