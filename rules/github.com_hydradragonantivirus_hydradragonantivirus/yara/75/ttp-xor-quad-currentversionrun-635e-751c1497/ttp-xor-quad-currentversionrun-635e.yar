rule TTP_XOR_QUAD_CurrentVersionRun_635e {
  strings:
    $key_635e = { 30 31 [2] 14 3f [2] 3f 13 [2] 11 31 [2] 05 2a [2] 0a 30 [2] 14 2d [2] 16 2c [2] 0d 2a [2] 11 2d [2] 0d 02 }

  condition:
    any of them
}