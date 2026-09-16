rule TTP_XOR_QUAD_CurrentVersionRun_445e {
  strings:
    $key_445e = { 17 31 [2] 33 3f [2] 18 13 [2] 36 31 [2] 22 2a [2] 2d 30 [2] 33 2d [2] 31 2c [2] 2a 2a [2] 36 2d [2] 2a 02 }

  condition:
    any of them
}