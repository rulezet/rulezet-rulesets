rule TTP_XOR_QUAD_CurrentVersionRun_0e4e {
  strings:
    $key_0e4e = { 5d 21 [2] 79 2f [2] 52 03 [2] 7c 21 [2] 68 3a [2] 67 20 [2] 79 3d [2] 7b 3c [2] 60 3a [2] 7c 3d [2] 60 12 }

  condition:
    any of them
}