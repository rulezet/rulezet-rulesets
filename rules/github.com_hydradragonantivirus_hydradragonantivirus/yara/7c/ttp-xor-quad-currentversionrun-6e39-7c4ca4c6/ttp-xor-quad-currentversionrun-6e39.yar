rule TTP_XOR_QUAD_CurrentVersionRun_6e39 {
  strings:
    $key_6e39 = { 3d 56 [2] 19 58 [2] 32 74 [2] 1c 56 [2] 08 4d [2] 07 57 [2] 19 4a [2] 1b 4b [2] 00 4d [2] 1c 4a [2] 00 65 }

  condition:
    any of them
}