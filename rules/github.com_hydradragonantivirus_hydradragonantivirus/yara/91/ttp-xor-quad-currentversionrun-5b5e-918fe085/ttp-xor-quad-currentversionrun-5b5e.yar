rule TTP_XOR_QUAD_CurrentVersionRun_5b5e {
  strings:
    $key_5b5e = { 08 31 [2] 2c 3f [2] 07 13 [2] 29 31 [2] 3d 2a [2] 32 30 [2] 2c 2d [2] 2e 2c [2] 35 2a [2] 29 2d [2] 35 02 }

  condition:
    any of them
}