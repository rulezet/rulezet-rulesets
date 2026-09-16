rule TTP_XOR_QUAD_CurrentVersionRun_6b6e {
  strings:
    $key_6b6e = { 38 01 [2] 1c 0f [2] 37 23 [2] 19 01 [2] 0d 1a [2] 02 00 [2] 1c 1d [2] 1e 1c [2] 05 1a [2] 19 1d [2] 05 32 }

  condition:
    any of them
}