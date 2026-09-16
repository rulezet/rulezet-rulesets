rule TTP_XOR_QUAD_CurrentVersionRun_3c6e {
  strings:
    $key_3c6e = { 6f 01 [2] 4b 0f [2] 60 23 [2] 4e 01 [2] 5a 1a [2] 55 00 [2] 4b 1d [2] 49 1c [2] 52 1a [2] 4e 1d [2] 52 32 }

  condition:
    any of them
}