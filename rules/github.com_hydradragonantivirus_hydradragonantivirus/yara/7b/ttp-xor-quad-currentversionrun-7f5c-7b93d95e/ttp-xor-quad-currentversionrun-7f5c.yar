rule TTP_XOR_QUAD_CurrentVersionRun_7f5c {
  strings:
    $key_7f5c = { 2c 33 [2] 08 3d [2] 23 11 [2] 0d 33 [2] 19 28 [2] 16 32 [2] 08 2f [2] 0a 2e [2] 11 28 [2] 0d 2f [2] 11 00 }

  condition:
    any of them
}