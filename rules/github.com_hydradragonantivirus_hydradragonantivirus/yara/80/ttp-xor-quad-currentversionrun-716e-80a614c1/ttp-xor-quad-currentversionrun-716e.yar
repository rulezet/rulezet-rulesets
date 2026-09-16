rule TTP_XOR_QUAD_CurrentVersionRun_716e {
  strings:
    $key_716e = { 22 01 [2] 06 0f [2] 2d 23 [2] 03 01 [2] 17 1a [2] 18 00 [2] 06 1d [2] 04 1c [2] 1f 1a [2] 03 1d [2] 1f 32 }

  condition:
    any of them
}