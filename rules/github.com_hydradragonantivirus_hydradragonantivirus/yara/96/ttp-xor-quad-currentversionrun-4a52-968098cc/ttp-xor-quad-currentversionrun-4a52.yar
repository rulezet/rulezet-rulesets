rule TTP_XOR_QUAD_CurrentVersionRun_4a52 {
  strings:
    $key_4a52 = { 19 3d [2] 3d 33 [2] 16 1f [2] 38 3d [2] 2c 26 [2] 23 3c [2] 3d 21 [2] 3f 20 [2] 24 26 [2] 38 21 [2] 24 0e }

  condition:
    any of them
}