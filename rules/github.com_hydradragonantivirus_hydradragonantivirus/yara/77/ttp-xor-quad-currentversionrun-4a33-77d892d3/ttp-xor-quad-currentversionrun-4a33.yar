rule TTP_XOR_QUAD_CurrentVersionRun_4a33 {
  strings:
    $key_4a33 = { 19 5c [2] 3d 52 [2] 16 7e [2] 38 5c [2] 2c 47 [2] 23 5d [2] 3d 40 [2] 3f 41 [2] 24 47 [2] 38 40 [2] 24 6f }

  condition:
    any of them
}