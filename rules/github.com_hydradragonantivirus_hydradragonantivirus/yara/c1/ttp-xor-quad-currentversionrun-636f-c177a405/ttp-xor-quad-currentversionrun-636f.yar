rule TTP_XOR_QUAD_CurrentVersionRun_636f {
  strings:
    $key_636f = { 30 00 [2] 14 0e [2] 3f 22 [2] 11 00 [2] 05 1b [2] 0a 01 [2] 14 1c [2] 16 1d [2] 0d 1b [2] 11 1c [2] 0d 33 }

  condition:
    any of them
}