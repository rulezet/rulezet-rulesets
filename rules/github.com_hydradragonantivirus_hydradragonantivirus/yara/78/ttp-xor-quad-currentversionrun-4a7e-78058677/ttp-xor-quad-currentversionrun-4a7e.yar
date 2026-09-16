rule TTP_XOR_QUAD_CurrentVersionRun_4a7e {
  strings:
    $key_4a7e = { 19 11 [2] 3d 1f [2] 16 33 [2] 38 11 [2] 2c 0a [2] 23 10 [2] 3d 0d [2] 3f 0c [2] 24 0a [2] 38 0d [2] 24 22 }

  condition:
    any of them
}