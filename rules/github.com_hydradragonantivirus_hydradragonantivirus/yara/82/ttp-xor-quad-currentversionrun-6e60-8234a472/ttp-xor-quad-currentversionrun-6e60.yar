rule TTP_XOR_QUAD_CurrentVersionRun_6e60 {
  strings:
    $key_6e60 = { 3d 0f [2] 19 01 [2] 32 2d [2] 1c 0f [2] 08 14 [2] 07 0e [2] 19 13 [2] 1b 12 [2] 00 14 [2] 1c 13 [2] 00 3c }

  condition:
    any of them
}