rule TTP_XOR_QUAD_CurrentVersionRun_0c6e {
  strings:
    $key_0c6e = { 5f 01 [2] 7b 0f [2] 50 23 [2] 7e 01 [2] 6a 1a [2] 65 00 [2] 7b 1d [2] 79 1c [2] 62 1a [2] 7e 1d [2] 62 32 }

  condition:
    any of them
}