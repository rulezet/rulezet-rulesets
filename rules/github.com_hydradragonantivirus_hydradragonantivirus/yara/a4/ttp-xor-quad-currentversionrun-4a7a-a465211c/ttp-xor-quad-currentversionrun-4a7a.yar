rule TTP_XOR_QUAD_CurrentVersionRun_4a7a {
  strings:
    $key_4a7a = { 19 15 [2] 3d 1b [2] 16 37 [2] 38 15 [2] 2c 0e [2] 23 14 [2] 3d 09 [2] 3f 08 [2] 24 0e [2] 38 09 [2] 24 26 }

  condition:
    any of them
}