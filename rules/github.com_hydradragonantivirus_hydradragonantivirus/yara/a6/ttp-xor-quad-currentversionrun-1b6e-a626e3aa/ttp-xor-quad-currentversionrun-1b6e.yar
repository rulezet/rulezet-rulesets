rule TTP_XOR_QUAD_CurrentVersionRun_1b6e {
  strings:
    $key_1b6e = { 48 01 [2] 6c 0f [2] 47 23 [2] 69 01 [2] 7d 1a [2] 72 00 [2] 6c 1d [2] 6e 1c [2] 75 1a [2] 69 1d [2] 75 32 }

  condition:
    any of them
}