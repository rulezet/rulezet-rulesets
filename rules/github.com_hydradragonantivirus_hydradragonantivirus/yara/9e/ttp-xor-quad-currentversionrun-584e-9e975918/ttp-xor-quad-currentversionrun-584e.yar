rule TTP_XOR_QUAD_CurrentVersionRun_584e {
  strings:
    $key_584e = { 0b 21 [2] 2f 2f [2] 04 03 [2] 2a 21 [2] 3e 3a [2] 31 20 [2] 2f 3d [2] 2d 3c [2] 36 3a [2] 2a 3d [2] 36 12 }

  condition:
    any of them
}