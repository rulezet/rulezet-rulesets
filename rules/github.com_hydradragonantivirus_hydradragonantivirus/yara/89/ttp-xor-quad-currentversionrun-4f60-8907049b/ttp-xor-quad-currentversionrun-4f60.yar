rule TTP_XOR_QUAD_CurrentVersionRun_4f60 {
  strings:
    $key_4f60 = { 1c 0f [2] 38 01 [2] 13 2d [2] 3d 0f [2] 29 14 [2] 26 0e [2] 38 13 [2] 3a 12 [2] 21 14 [2] 3d 13 [2] 21 3c }

  condition:
    any of them
}