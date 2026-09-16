rule TTP_XOR_QUAD_CurrentVersionRun_486e {
  strings:
    $key_486e = { 1b 01 [2] 3f 0f [2] 14 23 [2] 3a 01 [2] 2e 1a [2] 21 00 [2] 3f 1d [2] 3d 1c [2] 26 1a [2] 3a 1d [2] 26 32 }

  condition:
    any of them
}