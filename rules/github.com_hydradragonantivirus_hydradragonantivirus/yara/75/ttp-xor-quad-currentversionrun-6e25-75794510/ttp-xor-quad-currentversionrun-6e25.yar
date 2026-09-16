rule TTP_XOR_QUAD_CurrentVersionRun_6e25 {
  strings:
    $key_6e25 = { 3d 4a [2] 19 44 [2] 32 68 [2] 1c 4a [2] 08 51 [2] 07 4b [2] 19 56 [2] 1b 57 [2] 00 51 [2] 1c 56 [2] 00 79 }

  condition:
    any of them
}