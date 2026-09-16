rule TTP_XOR_QUAD_CurrentVersionRun_155e {
  strings:
    $key_155e = { 46 31 [2] 62 3f [2] 49 13 [2] 67 31 [2] 73 2a [2] 7c 30 [2] 62 2d [2] 60 2c [2] 7b 2a [2] 67 2d [2] 7b 02 }

  condition:
    any of them
}