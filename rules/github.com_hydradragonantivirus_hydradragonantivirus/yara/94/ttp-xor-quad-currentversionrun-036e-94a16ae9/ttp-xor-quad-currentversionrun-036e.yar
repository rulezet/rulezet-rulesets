rule TTP_XOR_QUAD_CurrentVersionRun_036e {
  strings:
    $key_036e = { 50 01 [2] 74 0f [2] 5f 23 [2] 71 01 [2] 65 1a [2] 6a 00 [2] 74 1d [2] 76 1c [2] 6d 1a [2] 71 1d [2] 6d 32 }

  condition:
    any of them
}