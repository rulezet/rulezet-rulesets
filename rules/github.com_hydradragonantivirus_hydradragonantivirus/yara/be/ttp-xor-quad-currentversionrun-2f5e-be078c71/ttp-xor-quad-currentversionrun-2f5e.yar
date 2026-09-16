rule TTP_XOR_QUAD_CurrentVersionRun_2f5e {
  strings:
    $key_2f5e = { 7c 31 [2] 58 3f [2] 73 13 [2] 5d 31 [2] 49 2a [2] 46 30 [2] 58 2d [2] 5a 2c [2] 41 2a [2] 5d 2d [2] 41 02 }

  condition:
    any of them
}