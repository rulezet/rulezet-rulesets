rule TTP_XOR_QUAD_CurrentVersionRun_fa5e {
  strings:
    $key_fa5e = { a9 31 [2] 8d 3f [2] a6 13 [2] 88 31 [2] 9c 2a [2] 93 30 [2] 8d 2d [2] 8f 2c [2] 94 2a [2] 88 2d [2] 94 02 }

  condition:
    any of them
}