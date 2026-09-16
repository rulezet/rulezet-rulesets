rule TTP_XOR_QUAD_CurrentVersionRun_6e63 {
  strings:
    $key_6e63 = { 3d 0c [2] 19 02 [2] 32 2e [2] 1c 0c [2] 08 17 [2] 07 0d [2] 19 10 [2] 1b 11 [2] 00 17 [2] 1c 10 [2] 00 3f }

  condition:
    any of them
}