rule TTP_XOR_QUAD_CurrentVersionRun_605e {
  strings:
    $key_605e = { 33 31 [2] 17 3f [2] 3c 13 [2] 12 31 [2] 06 2a [2] 09 30 [2] 17 2d [2] 15 2c [2] 0e 2a [2] 12 2d [2] 0e 02 }

  condition:
    any of them
}