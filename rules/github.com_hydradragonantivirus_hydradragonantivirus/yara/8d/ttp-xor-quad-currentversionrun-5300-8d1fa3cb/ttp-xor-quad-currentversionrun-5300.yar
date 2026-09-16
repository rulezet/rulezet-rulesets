rule TTP_XOR_QUAD_CurrentVersionRun_5300 {
  strings:
    $key_5300 = { 00 6f [2] 24 61 [2] 0f 4d [2] 21 6f [2] 35 74 [2] 3a 6e [2] 24 73 [2] 26 72 [2] 3d 74 [2] 21 73 [2] 3d 5c }

  condition:
    any of them
}