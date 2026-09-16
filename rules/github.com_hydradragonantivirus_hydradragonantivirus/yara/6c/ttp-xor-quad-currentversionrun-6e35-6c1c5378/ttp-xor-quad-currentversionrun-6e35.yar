rule TTP_XOR_QUAD_CurrentVersionRun_6e35 {
  strings:
    $key_6e35 = { 3d 5a [2] 19 54 [2] 32 78 [2] 1c 5a [2] 08 41 [2] 07 5b [2] 19 46 [2] 1b 47 [2] 00 41 [2] 1c 46 [2] 00 69 }

  condition:
    any of them
}