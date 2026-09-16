rule TTP_XOR_QUAD_CurrentVersionRun_7f4e {
  strings:
    $key_7f4e = { 2c 21 [2] 08 2f [2] 23 03 [2] 0d 21 [2] 19 3a [2] 16 20 [2] 08 3d [2] 0a 3c [2] 11 3a [2] 0d 3d [2] 11 12 }

  condition:
    any of them
}