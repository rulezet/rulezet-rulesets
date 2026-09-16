rule TTP_XOR_QUAD_CurrentVersionRun_486f {
  strings:
    $key_486f = { 1b 00 [2] 3f 0e [2] 14 22 [2] 3a 00 [2] 2e 1b [2] 21 01 [2] 3f 1c [2] 3d 1d [2] 26 1b [2] 3a 1c [2] 26 33 }

  condition:
    any of them
}