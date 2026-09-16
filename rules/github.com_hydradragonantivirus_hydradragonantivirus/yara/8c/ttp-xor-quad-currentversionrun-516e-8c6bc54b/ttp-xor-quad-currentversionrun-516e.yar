rule TTP_XOR_QUAD_CurrentVersionRun_516e {
  strings:
    $key_516e = { 02 01 [2] 26 0f [2] 0d 23 [2] 23 01 [2] 37 1a [2] 38 00 [2] 26 1d [2] 24 1c [2] 3f 1a [2] 23 1d [2] 3f 32 }

  condition:
    any of them
}