rule TTP_XOR_QUAD_CurrentVersionRun_644e {
  strings:
    $key_644e = { 37 21 [2] 13 2f [2] 38 03 [2] 16 21 [2] 02 3a [2] 0d 20 [2] 13 3d [2] 11 3c [2] 0a 3a [2] 16 3d [2] 0a 12 }

  condition:
    any of them
}