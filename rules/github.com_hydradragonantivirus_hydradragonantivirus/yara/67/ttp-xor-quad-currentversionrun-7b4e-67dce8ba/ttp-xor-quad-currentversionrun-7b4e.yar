rule TTP_XOR_QUAD_CurrentVersionRun_7b4e {
  strings:
    $key_7b4e = { 28 21 [2] 0c 2f [2] 27 03 [2] 09 21 [2] 1d 3a [2] 12 20 [2] 0c 3d [2] 0e 3c [2] 15 3a [2] 09 3d [2] 15 12 }

  condition:
    any of them
}