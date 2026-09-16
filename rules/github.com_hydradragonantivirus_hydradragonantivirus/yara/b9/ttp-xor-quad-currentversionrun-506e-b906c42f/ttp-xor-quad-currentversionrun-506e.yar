rule TTP_XOR_QUAD_CurrentVersionRun_506e {
  strings:
    $key_506e = { 03 01 [2] 27 0f [2] 0c 23 [2] 22 01 [2] 36 1a [2] 39 00 [2] 27 1d [2] 25 1c [2] 3e 1a [2] 22 1d [2] 3e 32 }

  condition:
    any of them
}