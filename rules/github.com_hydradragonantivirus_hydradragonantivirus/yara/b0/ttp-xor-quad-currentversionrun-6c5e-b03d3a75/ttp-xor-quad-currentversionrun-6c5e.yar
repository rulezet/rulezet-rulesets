rule TTP_XOR_QUAD_CurrentVersionRun_6c5e {
  strings:
    $key_6c5e = { 3f 31 [2] 1b 3f [2] 30 13 [2] 1e 31 [2] 0a 2a [2] 05 30 [2] 1b 2d [2] 19 2c [2] 02 2a [2] 1e 2d [2] 02 02 }

  condition:
    any of them
}