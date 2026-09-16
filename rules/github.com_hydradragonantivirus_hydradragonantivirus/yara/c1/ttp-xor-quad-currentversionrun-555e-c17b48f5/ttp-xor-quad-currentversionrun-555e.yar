rule TTP_XOR_QUAD_CurrentVersionRun_555e {
  strings:
    $key_555e = { 06 31 [2] 22 3f [2] 09 13 [2] 27 31 [2] 33 2a [2] 3c 30 [2] 22 2d [2] 20 2c [2] 3b 2a [2] 27 2d [2] 3b 02 }

  condition:
    any of them
}