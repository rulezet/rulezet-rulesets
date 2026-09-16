rule TTP_XOR_QUAD_CurrentVersionRun_7e4e {
  strings:
    $key_7e4e = { 2d 21 [2] 09 2f [2] 22 03 [2] 0c 21 [2] 18 3a [2] 17 20 [2] 09 3d [2] 0b 3c [2] 10 3a [2] 0c 3d [2] 10 12 }

  condition:
    any of them
}