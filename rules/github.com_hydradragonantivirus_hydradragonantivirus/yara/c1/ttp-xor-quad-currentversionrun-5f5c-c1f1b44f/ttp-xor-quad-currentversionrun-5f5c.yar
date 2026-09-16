rule TTP_XOR_QUAD_CurrentVersionRun_5f5c {
  strings:
    $key_5f5c = { 0c 33 [2] 28 3d [2] 03 11 [2] 2d 33 [2] 39 28 [2] 36 32 [2] 28 2f [2] 2a 2e [2] 31 28 [2] 2d 2f [2] 31 00 }

  condition:
    any of them
}