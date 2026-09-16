rule TTP_XOR_QUAD_CurrentVersionRun_1f6e {
  strings:
    $key_1f6e = { 4c 01 [2] 68 0f [2] 43 23 [2] 6d 01 [2] 79 1a [2] 76 00 [2] 68 1d [2] 6a 1c [2] 71 1a [2] 6d 1d [2] 71 32 }

  condition:
    any of them
}