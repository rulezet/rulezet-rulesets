rule TTP_XOR_QUAD_CurrentVersionRun_5460 {
  strings:
    $key_5460 = { 07 0f [2] 23 01 [2] 08 2d [2] 26 0f [2] 32 14 [2] 3d 0e [2] 23 13 [2] 21 12 [2] 3a 14 [2] 26 13 [2] 3a 3c }

  condition:
    any of them
}