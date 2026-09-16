rule TTP_XOR_QUAD_CurrentVersionRun_5161 {
  strings:
    $key_5161 = { 02 0e [2] 26 00 [2] 0d 2c [2] 23 0e [2] 37 15 [2] 38 0f [2] 26 12 [2] 24 13 [2] 3f 15 [2] 23 12 [2] 3f 3d }

  condition:
    any of them
}