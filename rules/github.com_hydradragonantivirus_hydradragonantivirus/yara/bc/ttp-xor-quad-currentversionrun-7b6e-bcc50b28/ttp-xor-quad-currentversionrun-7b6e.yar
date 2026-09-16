rule TTP_XOR_QUAD_CurrentVersionRun_7b6e {
  strings:
    $key_7b6e = { 28 01 [2] 0c 0f [2] 27 23 [2] 09 01 [2] 1d 1a [2] 12 00 [2] 0c 1d [2] 0e 1c [2] 15 1a [2] 09 1d [2] 15 32 }

  condition:
    any of them
}