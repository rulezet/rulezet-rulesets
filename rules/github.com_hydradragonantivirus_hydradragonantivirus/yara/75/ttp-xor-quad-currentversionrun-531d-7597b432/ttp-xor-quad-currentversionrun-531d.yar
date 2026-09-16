rule TTP_XOR_QUAD_CurrentVersionRun_531d {
  strings:
    $key_531d = { 00 72 [2] 24 7c [2] 0f 50 [2] 21 72 [2] 35 69 [2] 3a 73 [2] 24 6e [2] 26 6f [2] 3d 69 [2] 21 6e [2] 3d 41 }

  condition:
    any of them
}