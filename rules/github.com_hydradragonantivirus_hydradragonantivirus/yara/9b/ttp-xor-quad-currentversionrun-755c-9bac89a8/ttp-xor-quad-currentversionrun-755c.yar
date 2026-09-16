rule TTP_XOR_QUAD_CurrentVersionRun_755c {
  strings:
    $key_755c = { 26 33 [2] 02 3d [2] 29 11 [2] 07 33 [2] 13 28 [2] 1c 32 [2] 02 2f [2] 00 2e [2] 1b 28 [2] 07 2f [2] 1b 00 }

  condition:
    any of them
}