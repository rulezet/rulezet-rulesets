rule TTP_XOR_QUAD_CurrentVersionRun_534d {
  strings:
    $key_534d = { 00 22 [2] 24 2c [2] 0f 00 [2] 21 22 [2] 35 39 [2] 3a 23 [2] 24 3e [2] 26 3f [2] 3d 39 [2] 21 3e [2] 3d 11 }

  condition:
    any of them
}