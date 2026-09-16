rule TTP_XOR_QUAD_CurrentVersionRun_0c4e {
  strings:
    $key_0c4e = { 5f 21 [2] 7b 2f [2] 50 03 [2] 7e 21 [2] 6a 3a [2] 65 20 [2] 7b 3d [2] 79 3c [2] 62 3a [2] 7e 3d [2] 62 12 }

  condition:
    any of them
}