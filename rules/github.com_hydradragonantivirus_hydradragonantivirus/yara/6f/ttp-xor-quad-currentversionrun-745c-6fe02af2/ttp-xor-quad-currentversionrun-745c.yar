rule TTP_XOR_QUAD_CurrentVersionRun_745c {
  strings:
    $key_745c = { 27 33 [2] 03 3d [2] 28 11 [2] 06 33 [2] 12 28 [2] 1d 32 [2] 03 2f [2] 01 2e [2] 1a 28 [2] 06 2f [2] 1a 00 }

  condition:
    any of them
}