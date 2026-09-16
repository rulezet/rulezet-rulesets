rule TTP_XOR_QUAD_CurrentVersionRun_1a4e {
  strings:
    $key_1a4e = { 49 21 [2] 6d 2f [2] 46 03 [2] 68 21 [2] 7c 3a [2] 73 20 [2] 6d 3d [2] 6f 3c [2] 74 3a [2] 68 3d [2] 74 12 }

  condition:
    any of them
}