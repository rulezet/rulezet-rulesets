rule TTP_XOR_QUAD_CurrentVersionRun_065e {
  strings:
    $key_065e = { 55 31 [2] 71 3f [2] 5a 13 [2] 74 31 [2] 60 2a [2] 6f 30 [2] 71 2d [2] 73 2c [2] 68 2a [2] 74 2d [2] 68 02 }

  condition:
    any of them
}