rule TTP_XOR_QUAD_CurrentVersionRun_4a1d {
  strings:
    $key_4a1d = { 19 72 [2] 3d 7c [2] 16 50 [2] 38 72 [2] 2c 69 [2] 23 73 [2] 3d 6e [2] 3f 6f [2] 24 69 [2] 38 6e [2] 24 41 }

  condition:
    any of them
}