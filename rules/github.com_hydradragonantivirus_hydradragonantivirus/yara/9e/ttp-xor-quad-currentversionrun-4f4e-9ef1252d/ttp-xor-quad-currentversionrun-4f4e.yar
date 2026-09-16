rule TTP_XOR_QUAD_CurrentVersionRun_4f4e {
  strings:
    $key_4f4e = { 1c 21 [2] 38 2f [2] 13 03 [2] 3d 21 [2] 29 3a [2] 26 20 [2] 38 3d [2] 3a 3c [2] 21 3a [2] 3d 3d [2] 21 12 }

  condition:
    any of them
}