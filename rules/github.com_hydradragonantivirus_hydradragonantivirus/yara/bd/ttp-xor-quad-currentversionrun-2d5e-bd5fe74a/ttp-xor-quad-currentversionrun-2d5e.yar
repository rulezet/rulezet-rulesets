rule TTP_XOR_QUAD_CurrentVersionRun_2d5e {
  strings:
    $key_2d5e = { 7e 31 [2] 5a 3f [2] 71 13 [2] 5f 31 [2] 4b 2a [2] 44 30 [2] 5a 2d [2] 58 2c [2] 43 2a [2] 5f 2d [2] 43 02 }

  condition:
    any of them
}