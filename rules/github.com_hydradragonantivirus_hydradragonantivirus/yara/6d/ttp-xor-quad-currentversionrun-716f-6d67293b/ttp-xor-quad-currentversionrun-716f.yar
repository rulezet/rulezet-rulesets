rule TTP_XOR_QUAD_CurrentVersionRun_716f {
  strings:
    $key_716f = { 22 00 [2] 06 0e [2] 2d 22 [2] 03 00 [2] 17 1b [2] 18 01 [2] 06 1c [2] 04 1d [2] 1f 1b [2] 03 1c [2] 1f 33 }

  condition:
    any of them
}