rule TTP_XOR_QUAD_CurrentVersionRun_1f4e {
  strings:
    $key_1f4e = { 4c 21 [2] 68 2f [2] 43 03 [2] 6d 21 [2] 79 3a [2] 76 20 [2] 68 3d [2] 6a 3c [2] 71 3a [2] 6d 3d [2] 71 12 }

  condition:
    any of them
}