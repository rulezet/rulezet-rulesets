rule TTP_XOR_QUAD_CurrentVersionRun_6f5e {
  strings:
    $key_6f5e = { 3c 31 [2] 18 3f [2] 33 13 [2] 1d 31 [2] 09 2a [2] 06 30 [2] 18 2d [2] 1a 2c [2] 01 2a [2] 1d 2d [2] 01 02 }

  condition:
    any of them
}