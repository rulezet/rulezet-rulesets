rule TTP_XOR_QUAD_CurrentVersionRun_546f {
  strings:
    $key_546f = { 07 00 [2] 23 0e [2] 08 22 [2] 26 00 [2] 32 1b [2] 3d 01 [2] 23 1c [2] 21 1d [2] 3a 1b [2] 26 1c [2] 3a 33 }

  condition:
    any of them
}