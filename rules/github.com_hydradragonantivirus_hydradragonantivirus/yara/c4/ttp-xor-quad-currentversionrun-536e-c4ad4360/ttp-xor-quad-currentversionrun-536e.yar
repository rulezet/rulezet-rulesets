rule TTP_XOR_QUAD_CurrentVersionRun_536e {
  strings:
    $key_536e = { 00 01 [2] 24 0f [2] 0f 23 [2] 21 01 [2] 35 1a [2] 3a 00 [2] 24 1d [2] 26 1c [2] 3d 1a [2] 21 1d [2] 3d 32 }

  condition:
    any of them
}