rule TTP_XOR_QUAD_CurrentVersionRun_566e {
  strings:
    $key_566e = { 05 01 [2] 21 0f [2] 0a 23 [2] 24 01 [2] 30 1a [2] 3f 00 [2] 21 1d [2] 23 1c [2] 38 1a [2] 24 1d [2] 38 32 }

  condition:
    any of them
}