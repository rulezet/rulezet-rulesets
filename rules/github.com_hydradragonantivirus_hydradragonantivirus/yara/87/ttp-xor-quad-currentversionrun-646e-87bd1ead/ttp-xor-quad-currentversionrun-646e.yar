rule TTP_XOR_QUAD_CurrentVersionRun_646e {
  strings:
    $key_646e = { 37 01 [2] 13 0f [2] 38 23 [2] 16 01 [2] 02 1a [2] 0d 00 [2] 13 1d [2] 11 1c [2] 0a 1a [2] 16 1d [2] 0a 32 }

  condition:
    any of them
}