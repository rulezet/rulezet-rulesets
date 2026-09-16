rule TTP_XOR_QUAD_CurrentVersionRun_6e4d {
  strings:
    $key_6e4d = { 3d 22 [2] 19 2c [2] 32 00 [2] 1c 22 [2] 08 39 [2] 07 23 [2] 19 3e [2] 1b 3f [2] 00 39 [2] 1c 3e [2] 00 11 }

  condition:
    any of them
}