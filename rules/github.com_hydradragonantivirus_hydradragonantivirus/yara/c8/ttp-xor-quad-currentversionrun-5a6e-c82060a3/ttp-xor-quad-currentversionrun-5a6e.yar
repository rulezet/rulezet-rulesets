rule TTP_XOR_QUAD_CurrentVersionRun_5a6e {
  strings:
    $key_5a6e = { 09 01 [2] 2d 0f [2] 06 23 [2] 28 01 [2] 3c 1a [2] 33 00 [2] 2d 1d [2] 2f 1c [2] 34 1a [2] 28 1d [2] 34 32 }

  condition:
    any of them
}