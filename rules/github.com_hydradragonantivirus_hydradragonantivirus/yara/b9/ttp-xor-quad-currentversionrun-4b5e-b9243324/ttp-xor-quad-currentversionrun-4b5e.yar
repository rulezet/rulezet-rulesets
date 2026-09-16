rule TTP_XOR_QUAD_CurrentVersionRun_4b5e {
  strings:
    $key_4b5e = { 18 31 [2] 3c 3f [2] 17 13 [2] 39 31 [2] 2d 2a [2] 22 30 [2] 3c 2d [2] 3e 2c [2] 25 2a [2] 39 2d [2] 25 02 }

  condition:
    any of them
}