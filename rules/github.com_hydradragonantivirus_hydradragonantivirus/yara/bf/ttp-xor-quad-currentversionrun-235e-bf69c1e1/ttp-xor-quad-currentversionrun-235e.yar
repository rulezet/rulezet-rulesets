rule TTP_XOR_QUAD_CurrentVersionRun_235e {
  strings:
    $key_235e = { 70 31 [2] 54 3f [2] 7f 13 [2] 51 31 [2] 45 2a [2] 4a 30 [2] 54 2d [2] 56 2c [2] 4d 2a [2] 51 2d [2] 4d 02 }

  condition:
    any of them
}