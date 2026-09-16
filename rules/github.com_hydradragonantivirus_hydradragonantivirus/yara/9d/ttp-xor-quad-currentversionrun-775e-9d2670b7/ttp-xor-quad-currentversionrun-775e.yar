rule TTP_XOR_QUAD_CurrentVersionRun_775e {
  strings:
    $key_775e = { 24 31 [2] 00 3f [2] 2b 13 [2] 05 31 [2] 11 2a [2] 1e 30 [2] 00 2d [2] 02 2c [2] 19 2a [2] 05 2d [2] 19 02 }

  condition:
    any of them
}