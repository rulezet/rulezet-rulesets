rule TTP_XOR_QUAD_CurrentVersionRun_725e {
  strings:
    $key_725e = { 21 31 [2] 05 3f [2] 2e 13 [2] 00 31 [2] 14 2a [2] 1b 30 [2] 05 2d [2] 07 2c [2] 1c 2a [2] 00 2d [2] 1c 02 }

  condition:
    any of them
}