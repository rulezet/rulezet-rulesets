rule TTP_XOR_QUAD_CurrentVersionRun_6e7c {
  strings:
    $key_6e7c = { 3d 13 [2] 19 1d [2] 32 31 [2] 1c 13 [2] 08 08 [2] 07 12 [2] 19 0f [2] 1b 0e [2] 00 08 [2] 1c 0f [2] 00 20 }

  condition:
    any of them
}