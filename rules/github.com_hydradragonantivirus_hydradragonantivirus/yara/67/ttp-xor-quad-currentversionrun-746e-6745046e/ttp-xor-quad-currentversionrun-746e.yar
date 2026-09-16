rule TTP_XOR_QUAD_CurrentVersionRun_746e {
  strings:
    $key_746e = { 27 01 [2] 03 0f [2] 28 23 [2] 06 01 [2] 12 1a [2] 1d 00 [2] 03 1d [2] 01 1c [2] 1a 1a [2] 06 1d [2] 1a 32 }

  condition:
    any of them
}