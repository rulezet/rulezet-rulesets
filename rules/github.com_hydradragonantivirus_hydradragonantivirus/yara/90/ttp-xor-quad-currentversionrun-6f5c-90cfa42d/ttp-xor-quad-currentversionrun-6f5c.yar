rule TTP_XOR_QUAD_CurrentVersionRun_6f5c {
  strings:
    $key_6f5c = { 3c 33 [2] 18 3d [2] 33 11 [2] 1d 33 [2] 09 28 [2] 06 32 [2] 18 2f [2] 1a 2e [2] 01 28 [2] 1d 2f [2] 01 00 }

  condition:
    any of them
}