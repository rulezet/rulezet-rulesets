rule TTP_XOR_QUAD_CurrentVersionRun_1d4e {
  strings:
    $key_1d4e = { 4e 21 [2] 6a 2f [2] 41 03 [2] 6f 21 [2] 7b 3a [2] 74 20 [2] 6a 3d [2] 68 3c [2] 73 3a [2] 6f 3d [2] 73 12 }

  condition:
    any of them
}