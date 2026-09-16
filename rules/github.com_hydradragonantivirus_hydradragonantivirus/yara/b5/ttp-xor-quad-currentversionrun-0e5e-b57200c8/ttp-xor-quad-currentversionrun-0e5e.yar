rule TTP_XOR_QUAD_CurrentVersionRun_0e5e {
  strings:
    $key_0e5e = { 5d 31 [2] 79 3f [2] 52 13 [2] 7c 31 [2] 68 2a [2] 67 30 [2] 79 2d [2] 7b 2c [2] 60 2a [2] 7c 2d [2] 60 02 }

  condition:
    any of them
}