rule TTP_XOR_QUAD_CurrentVersionRun_5e52 {
  strings:
    $key_5e52 = { 0d 3d [2] 29 33 [2] 02 1f [2] 2c 3d [2] 38 26 [2] 37 3c [2] 29 21 [2] 2b 20 [2] 30 26 [2] 2c 21 [2] 30 0e }

  condition:
    any of them
}