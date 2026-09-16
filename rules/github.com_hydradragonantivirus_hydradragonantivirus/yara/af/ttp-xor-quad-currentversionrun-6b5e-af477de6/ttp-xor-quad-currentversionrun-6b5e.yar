rule TTP_XOR_QUAD_CurrentVersionRun_6b5e {
  strings:
    $key_6b5e = { 38 31 [2] 1c 3f [2] 37 13 [2] 19 31 [2] 0d 2a [2] 02 30 [2] 1c 2d [2] 1e 2c [2] 05 2a [2] 19 2d [2] 05 02 }

  condition:
    any of them
}