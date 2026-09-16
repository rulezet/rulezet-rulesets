rule TTP_XOR_QUAD_CurrentVersionRun_5e4e {
  strings:
    $key_5e4e = { 0d 21 [2] 29 2f [2] 02 03 [2] 2c 21 [2] 38 3a [2] 37 20 [2] 29 3d [2] 2b 3c [2] 30 3a [2] 2c 3d [2] 30 12 }

  condition:
    any of them
}