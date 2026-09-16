rule TTP_XOR_QUAD_CurrentVersionRun_6e6e {
  strings:
    $key_6e6e = { 3d 01 [2] 19 0f [2] 32 23 [2] 1c 01 [2] 08 1a [2] 07 00 [2] 19 1d [2] 1b 1c [2] 00 1a [2] 1c 1d [2] 00 32 }

  condition:
    any of them
}