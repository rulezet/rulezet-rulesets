rule TTP_XOR_QUAD_CurrentVersionRun_743e {
  strings:
    $key_743e = { 27 51 [2] 03 5f [2] 28 73 [2] 06 51 [2] 12 4a [2] 1d 50 [2] 03 4d [2] 01 4c [2] 1a 4a [2] 06 4d [2] 1a 62 }

  condition:
    any of them
}