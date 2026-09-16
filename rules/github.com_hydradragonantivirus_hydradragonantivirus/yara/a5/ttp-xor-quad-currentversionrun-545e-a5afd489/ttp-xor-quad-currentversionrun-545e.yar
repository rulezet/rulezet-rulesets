rule TTP_XOR_QUAD_CurrentVersionRun_545e {
  strings:
    $key_545e = { 07 31 [2] 23 3f [2] 08 13 [2] 26 31 [2] 32 2a [2] 3d 30 [2] 23 2d [2] 21 2c [2] 3a 2a [2] 26 2d [2] 3a 02 }

  condition:
    any of them
}