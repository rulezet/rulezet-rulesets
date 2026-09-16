rule TTP_XOR_QUAD_CurrentVersionRun_5f4d {
  strings:
    $key_5f4d = { 0c 22 [2] 28 2c [2] 03 00 [2] 2d 22 [2] 39 39 [2] 36 23 [2] 28 3e [2] 2a 3f [2] 31 39 [2] 2d 3e [2] 31 11 }

  condition:
    any of them
}