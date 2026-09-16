rule TTP_XOR_QUAD_CurrentVersionRun_6e5d {
  strings:
    $key_6e5d = { 3d 32 [2] 19 3c [2] 32 10 [2] 1c 32 [2] 08 29 [2] 07 33 [2] 19 2e [2] 1b 2f [2] 00 29 [2] 1c 2e [2] 00 01 }

  condition:
    any of them
}