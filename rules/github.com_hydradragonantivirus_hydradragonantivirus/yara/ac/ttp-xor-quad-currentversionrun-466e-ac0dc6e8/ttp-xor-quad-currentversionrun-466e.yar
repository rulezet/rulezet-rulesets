rule TTP_XOR_QUAD_CurrentVersionRun_466e {
  strings:
    $key_466e = { 15 01 [2] 31 0f [2] 1a 23 [2] 34 01 [2] 20 1a [2] 2f 00 [2] 31 1d [2] 33 1c [2] 28 1a [2] 34 1d [2] 28 32 }

  condition:
    any of them
}