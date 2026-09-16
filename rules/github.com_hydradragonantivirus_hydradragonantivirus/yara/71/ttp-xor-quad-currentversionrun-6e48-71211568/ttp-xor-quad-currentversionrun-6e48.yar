rule TTP_XOR_QUAD_CurrentVersionRun_6e48 {
  strings:
    $key_6e48 = { 3d 27 [2] 19 29 [2] 32 05 [2] 1c 27 [2] 08 3c [2] 07 26 [2] 19 3b [2] 1b 3a [2] 00 3c [2] 1c 3b [2] 00 14 }

  condition:
    any of them
}