rule TTP_XOR_QUAD_CurrentVersionRun_3e4e {
  strings:
    $key_3e4e = { 6d 21 [2] 49 2f [2] 62 03 [2] 4c 21 [2] 58 3a [2] 57 20 [2] 49 3d [2] 4b 3c [2] 50 3a [2] 4c 3d [2] 50 12 }

  condition:
    any of them
}