rule TTP_XOR_QUAD_CurrentVersionRun_1a6e {
  strings:
    $key_1a6e = { 49 01 [2] 6d 0f [2] 46 23 [2] 68 01 [2] 7c 1a [2] 73 00 [2] 6d 1d [2] 6f 1c [2] 74 1a [2] 68 1d [2] 74 32 }

  condition:
    any of them
}