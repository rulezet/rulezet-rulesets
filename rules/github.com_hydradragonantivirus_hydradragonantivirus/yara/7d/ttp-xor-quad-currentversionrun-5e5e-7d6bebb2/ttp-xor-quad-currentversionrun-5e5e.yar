rule TTP_XOR_QUAD_CurrentVersionRun_5e5e {
  strings:
    $key_5e5e = { 0d 31 [2] 29 3f [2] 02 13 [2] 2c 31 [2] 38 2a [2] 37 30 [2] 29 2d [2] 2b 2c [2] 30 2a [2] 2c 2d [2] 30 02 }

  condition:
    any of them
}