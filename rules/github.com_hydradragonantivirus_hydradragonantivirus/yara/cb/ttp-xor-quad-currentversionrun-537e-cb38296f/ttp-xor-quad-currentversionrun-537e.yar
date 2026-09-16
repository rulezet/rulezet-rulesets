rule TTP_XOR_QUAD_CurrentVersionRun_537e {
  strings:
    $key_537e = { 00 11 [2] 24 1f [2] 0f 33 [2] 21 11 [2] 35 0a [2] 3a 10 [2] 24 0d [2] 26 0c [2] 3d 0a [2] 21 0d [2] 3d 22 }

  condition:
    any of them
}