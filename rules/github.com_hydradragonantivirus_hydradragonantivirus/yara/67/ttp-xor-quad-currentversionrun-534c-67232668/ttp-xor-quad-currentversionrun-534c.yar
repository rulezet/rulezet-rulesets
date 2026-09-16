rule TTP_XOR_QUAD_CurrentVersionRun_534c {
  strings:
    $key_534c = { 00 23 [2] 24 2d [2] 0f 01 [2] 21 23 [2] 35 38 [2] 3a 22 [2] 24 3f [2] 26 3e [2] 3d 38 [2] 21 3f [2] 3d 10 }

  condition:
    any of them
}