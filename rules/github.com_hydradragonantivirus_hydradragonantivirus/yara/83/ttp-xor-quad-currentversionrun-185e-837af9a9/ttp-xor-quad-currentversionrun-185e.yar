rule TTP_XOR_QUAD_CurrentVersionRun_185e {
  strings:
    $key_185e = { 4b 31 [2] 6f 3f [2] 44 13 [2] 6a 31 [2] 7e 2a [2] 71 30 [2] 6f 2d [2] 6d 2c [2] 76 2a [2] 6a 2d [2] 76 02 }

  condition:
    any of them
}