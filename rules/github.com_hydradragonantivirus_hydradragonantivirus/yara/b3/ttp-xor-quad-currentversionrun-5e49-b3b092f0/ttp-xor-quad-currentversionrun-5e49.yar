rule TTP_XOR_QUAD_CurrentVersionRun_5e49 {
  strings:
    $key_5e49 = { 0d 26 [2] 29 28 [2] 02 04 [2] 2c 26 [2] 38 3d [2] 37 27 [2] 29 3a [2] 2b 3b [2] 30 3d [2] 2c 3a [2] 30 15 }

  condition:
    any of them
}