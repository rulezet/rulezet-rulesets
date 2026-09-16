rule TTP_XOR_QUAD_CurrentVersionRun_4b6e {
  strings:
    $key_4b6e = { 18 01 [2] 3c 0f [2] 17 23 [2] 39 01 [2] 2d 1a [2] 22 00 [2] 3c 1d [2] 3e 1c [2] 25 1a [2] 39 1d [2] 25 32 }

  condition:
    any of them
}