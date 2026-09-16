rule TTP_XOR_QUAD_CurrentVersionRun_1b5e {
  strings:
    $key_1b5e = { 48 31 [2] 6c 3f [2] 47 13 [2] 69 31 [2] 7d 2a [2] 72 30 [2] 6c 2d [2] 6e 2c [2] 75 2a [2] 69 2d [2] 75 02 }

  condition:
    any of them
}