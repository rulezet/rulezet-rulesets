rule TTP_XOR_QUAD_CurrentVersionRun_705e {
  strings:
    $key_705e = { 23 31 [2] 07 3f [2] 2c 13 [2] 02 31 [2] 16 2a [2] 19 30 [2] 07 2d [2] 05 2c [2] 1e 2a [2] 02 2d [2] 1e 02 }

  condition:
    any of them
}