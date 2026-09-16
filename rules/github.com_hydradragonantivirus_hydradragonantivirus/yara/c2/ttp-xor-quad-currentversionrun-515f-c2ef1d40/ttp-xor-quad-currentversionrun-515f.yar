rule TTP_XOR_QUAD_CurrentVersionRun_515f {
  strings:
    $key_515f = { 02 30 [2] 26 3e [2] 0d 12 [2] 23 30 [2] 37 2b [2] 38 31 [2] 26 2c [2] 24 2d [2] 3f 2b [2] 23 2c [2] 3f 03 }

  condition:
    any of them
}