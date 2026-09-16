rule TTP_XOR_QUAD_CurrentVersionRun_715e {
  strings:
    $key_715e = { 22 31 [2] 06 3f [2] 2d 13 [2] 03 31 [2] 17 2a [2] 18 30 [2] 06 2d [2] 04 2c [2] 1f 2a [2] 03 2d [2] 1f 02 }

  condition:
    any of them
}