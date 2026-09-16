rule TTP_XOR_QUAD_CurrentVersionRun_676e {
  strings:
    $key_676e = { 34 01 [2] 10 0f [2] 3b 23 [2] 15 01 [2] 01 1a [2] 0e 00 [2] 10 1d [2] 12 1c [2] 09 1a [2] 15 1d [2] 09 32 }

  condition:
    any of them
}