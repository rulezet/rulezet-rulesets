rule TTP_XOR_QUAD_CurrentVersionRun_225e {
  strings:
    $key_225e = { 71 31 [2] 55 3f [2] 7e 13 [2] 50 31 [2] 44 2a [2] 4b 30 [2] 55 2d [2] 57 2c [2] 4c 2a [2] 50 2d [2] 4c 02 }

  condition:
    any of them
}