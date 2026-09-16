rule TTP_XOR_QUAD_CurrentVersionRun_5a5e {
  strings:
    $key_5a5e = { 09 31 [2] 2d 3f [2] 06 13 [2] 28 31 [2] 3c 2a [2] 33 30 [2] 2d 2d [2] 2f 2c [2] 34 2a [2] 28 2d [2] 34 02 }

  condition:
    any of them
}