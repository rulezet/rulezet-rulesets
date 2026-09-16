rule TTP_XOR_QUAD_CurrentVersionRun_315f {
  strings:
    $key_315f = { 62 30 [2] 46 3e [2] 6d 12 [2] 43 30 [2] 57 2b [2] 58 31 [2] 46 2c [2] 44 2d [2] 5f 2b [2] 43 2c [2] 5f 03 }

  condition:
    any of them
}