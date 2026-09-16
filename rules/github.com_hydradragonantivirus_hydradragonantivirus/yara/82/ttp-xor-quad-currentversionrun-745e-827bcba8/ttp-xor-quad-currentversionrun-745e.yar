rule TTP_XOR_QUAD_CurrentVersionRun_745e {
  strings:
    $key_745e = { 27 31 [2] 03 3f [2] 28 13 [2] 06 31 [2] 12 2a [2] 1d 30 [2] 03 2d [2] 01 2c [2] 1a 2a [2] 06 2d [2] 1a 02 }

  condition:
    any of them
}