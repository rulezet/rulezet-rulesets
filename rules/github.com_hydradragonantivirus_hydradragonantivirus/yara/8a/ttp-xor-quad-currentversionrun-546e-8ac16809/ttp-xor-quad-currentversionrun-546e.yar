rule TTP_XOR_QUAD_CurrentVersionRun_546e {
  strings:
    $key_546e = { 07 01 [2] 23 0f [2] 08 23 [2] 26 01 [2] 32 1a [2] 3d 00 [2] 23 1d [2] 21 1c [2] 3a 1a [2] 26 1d [2] 3a 32 }

  condition:
    any of them
}