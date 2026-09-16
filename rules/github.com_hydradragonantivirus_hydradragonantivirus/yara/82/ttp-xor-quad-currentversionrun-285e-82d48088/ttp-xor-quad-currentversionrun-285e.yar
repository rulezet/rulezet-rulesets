rule TTP_XOR_QUAD_CurrentVersionRun_285e {
  strings:
    $key_285e = { 7b 31 [2] 5f 3f [2] 74 13 [2] 5a 31 [2] 4e 2a [2] 41 30 [2] 5f 2d [2] 5d 2c [2] 46 2a [2] 5a 2d [2] 46 02 }

  condition:
    any of them
}