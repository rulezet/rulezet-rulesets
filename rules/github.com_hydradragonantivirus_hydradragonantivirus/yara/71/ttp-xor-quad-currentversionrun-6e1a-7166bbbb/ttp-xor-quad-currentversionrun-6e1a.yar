rule TTP_XOR_QUAD_CurrentVersionRun_6e1a {
  strings:
    $key_6e1a = { 3d 75 [2] 19 7b [2] 32 57 [2] 1c 75 [2] 08 6e [2] 07 74 [2] 19 69 [2] 1b 68 [2] 00 6e [2] 1c 69 [2] 00 46 }

  condition:
    any of them
}