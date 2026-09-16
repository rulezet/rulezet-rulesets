rule TTP_XOR_QUAD_CurrentVersionRun_6e5c {
  strings:
    $key_6e5c = { 3d 33 [2] 19 3d [2] 32 11 [2] 1c 33 [2] 08 28 [2] 07 32 [2] 19 2f [2] 1b 2e [2] 00 28 [2] 1c 2f [2] 00 00 }

  condition:
    any of them
}