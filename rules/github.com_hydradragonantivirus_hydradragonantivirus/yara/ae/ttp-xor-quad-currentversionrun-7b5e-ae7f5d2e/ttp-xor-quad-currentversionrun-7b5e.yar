rule TTP_XOR_QUAD_CurrentVersionRun_7b5e {
  strings:
    $key_7b5e = { 28 31 [2] 0c 3f [2] 27 13 [2] 09 31 [2] 1d 2a [2] 12 30 [2] 0c 2d [2] 0e 2c [2] 15 2a [2] 09 2d [2] 15 02 }

  condition:
    any of them
}