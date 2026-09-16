rule TTP_XOR_QUAD_CurrentVersionRun_076e {
  strings:
    $key_076e = { 54 01 [2] 70 0f [2] 5b 23 [2] 75 01 [2] 61 1a [2] 6e 00 [2] 70 1d [2] 72 1c [2] 69 1a [2] 75 1d [2] 69 32 }

  condition:
    any of them
}