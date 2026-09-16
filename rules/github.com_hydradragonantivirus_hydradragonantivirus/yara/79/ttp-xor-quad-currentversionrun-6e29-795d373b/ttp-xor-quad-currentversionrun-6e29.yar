rule TTP_XOR_QUAD_CurrentVersionRun_6e29 {
  strings:
    $key_6e29 = { 3d 46 [2] 19 48 [2] 32 64 [2] 1c 46 [2] 08 5d [2] 07 47 [2] 19 5a [2] 1b 5b [2] 00 5d [2] 1c 5a [2] 00 75 }

  condition:
    any of them
}