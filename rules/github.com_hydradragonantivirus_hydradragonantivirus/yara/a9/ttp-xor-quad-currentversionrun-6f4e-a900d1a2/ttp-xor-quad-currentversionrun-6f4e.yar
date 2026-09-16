rule TTP_XOR_QUAD_CurrentVersionRun_6f4e {
  strings:
    $key_6f4e = { 3c 21 [2] 18 2f [2] 33 03 [2] 1d 21 [2] 09 3a [2] 06 20 [2] 18 3d [2] 1a 3c [2] 01 3a [2] 1d 3d [2] 01 12 }

  condition:
    any of them
}