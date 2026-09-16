rule TTP_XOR_QUAD_CurrentVersionRun_0e6e {
  strings:
    $key_0e6e = { 5d 01 [2] 79 0f [2] 52 23 [2] 7c 01 [2] 68 1a [2] 67 00 [2] 79 1d [2] 7b 1c [2] 60 1a [2] 7c 1d [2] 60 32 }

  condition:
    any of them
}