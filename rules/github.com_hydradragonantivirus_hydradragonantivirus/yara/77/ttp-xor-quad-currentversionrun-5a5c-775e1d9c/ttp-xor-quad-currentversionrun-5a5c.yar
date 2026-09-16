rule TTP_XOR_QUAD_CurrentVersionRun_5a5c {
  strings:
    $key_5a5c = { 09 33 [2] 2d 3d [2] 06 11 [2] 28 33 [2] 3c 28 [2] 33 32 [2] 2d 2f [2] 2f 2e [2] 34 28 [2] 28 2f [2] 34 00 }

  condition:
    any of them
}