rule TTP_XOR_QUAD_CurrentVersionRun_734e {
  strings:
    $key_734e = { 20 21 [2] 04 2f [2] 2f 03 [2] 01 21 [2] 15 3a [2] 1a 20 [2] 04 3d [2] 06 3c [2] 1d 3a [2] 01 3d [2] 1d 12 }

  condition:
    any of them
}