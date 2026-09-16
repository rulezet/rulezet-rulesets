rule TTP_XOR_QUAD_CurrentVersionRun_4c5e {
  strings:
    $key_4c5e = { 1f 31 [2] 3b 3f [2] 10 13 [2] 3e 31 [2] 2a 2a [2] 25 30 [2] 3b 2d [2] 39 2c [2] 22 2a [2] 3e 2d [2] 22 02 }

  condition:
    any of them
}