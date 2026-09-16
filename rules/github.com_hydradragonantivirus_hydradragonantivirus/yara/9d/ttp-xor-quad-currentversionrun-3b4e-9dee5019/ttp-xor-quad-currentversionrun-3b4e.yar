rule TTP_XOR_QUAD_CurrentVersionRun_3b4e {
  strings:
    $key_3b4e = { 68 21 [2] 4c 2f [2] 67 03 [2] 49 21 [2] 5d 3a [2] 52 20 [2] 4c 3d [2] 4e 3c [2] 55 3a [2] 49 3d [2] 55 12 }

  condition:
    any of them
}