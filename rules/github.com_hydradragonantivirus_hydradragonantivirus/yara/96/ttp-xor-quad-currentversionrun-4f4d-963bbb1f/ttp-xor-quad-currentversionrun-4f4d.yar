rule TTP_XOR_QUAD_CurrentVersionRun_4f4d {
  strings:
    $key_4f4d = { 1c 22 [2] 38 2c [2] 13 00 [2] 3d 22 [2] 29 39 [2] 26 23 [2] 38 3e [2] 3a 3f [2] 21 39 [2] 3d 3e [2] 21 11 }

  condition:
    any of them
}