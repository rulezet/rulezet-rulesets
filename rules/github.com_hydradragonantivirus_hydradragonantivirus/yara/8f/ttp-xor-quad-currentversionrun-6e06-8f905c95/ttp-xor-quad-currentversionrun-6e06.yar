rule TTP_XOR_QUAD_CurrentVersionRun_6e06 {
  strings:
    $key_6e06 = { 3d 69 [2] 19 67 [2] 32 4b [2] 1c 69 [2] 08 72 [2] 07 68 [2] 19 75 [2] 1b 74 [2] 00 72 [2] 1c 75 [2] 00 5a }

  condition:
    any of them
}