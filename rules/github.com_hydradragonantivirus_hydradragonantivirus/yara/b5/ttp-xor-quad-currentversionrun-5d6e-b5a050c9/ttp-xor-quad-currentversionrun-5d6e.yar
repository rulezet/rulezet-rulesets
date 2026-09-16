rule TTP_XOR_QUAD_CurrentVersionRun_5d6e {
  strings:
    $key_5d6e = { 0e 01 [2] 2a 0f [2] 01 23 [2] 2f 01 [2] 3b 1a [2] 34 00 [2] 2a 1d [2] 28 1c [2] 33 1a [2] 2f 1d [2] 33 32 }

  condition:
    any of them
}