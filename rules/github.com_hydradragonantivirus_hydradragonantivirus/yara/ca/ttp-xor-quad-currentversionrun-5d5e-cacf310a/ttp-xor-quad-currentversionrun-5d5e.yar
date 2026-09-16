rule TTP_XOR_QUAD_CurrentVersionRun_5d5e {
  strings:
    $key_5d5e = { 0e 31 [2] 2a 3f [2] 01 13 [2] 2f 31 [2] 3b 2a [2] 34 30 [2] 2a 2d [2] 28 2c [2] 33 2a [2] 2f 2d [2] 33 02 }

  condition:
    any of them
}