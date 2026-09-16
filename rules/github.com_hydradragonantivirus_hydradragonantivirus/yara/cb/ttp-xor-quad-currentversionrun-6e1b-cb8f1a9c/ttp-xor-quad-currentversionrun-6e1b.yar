rule TTP_XOR_QUAD_CurrentVersionRun_6e1b {
  strings:
    $key_6e1b = { 3d 74 [2] 19 7a [2] 32 56 [2] 1c 74 [2] 08 6f [2] 07 75 [2] 19 68 [2] 1b 69 [2] 00 6f [2] 1c 68 [2] 00 47 }

  condition:
    any of them
}