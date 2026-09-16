rule TTP_XOR_QUAD_CurrentVersionRun_335e {
  strings:
    $key_335e = { 60 31 [2] 44 3f [2] 6f 13 [2] 41 31 [2] 55 2a [2] 5a 30 [2] 44 2d [2] 46 2c [2] 5d 2a [2] 41 2d [2] 5d 02 }

  condition:
    any of them
}