rule TTP_XOR_QUAD_CurrentVersionRun_4a61 {
  strings:
    $key_4a61 = { 19 0e [2] 3d 00 [2] 16 2c [2] 38 0e [2] 2c 15 [2] 23 0f [2] 3d 12 [2] 3f 13 [2] 24 15 [2] 38 12 [2] 24 3d }

  condition:
    any of them
}