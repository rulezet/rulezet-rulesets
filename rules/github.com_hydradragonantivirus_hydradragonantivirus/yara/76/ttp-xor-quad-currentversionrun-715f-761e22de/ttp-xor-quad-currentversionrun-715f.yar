rule TTP_XOR_QUAD_CurrentVersionRun_715f {
  strings:
    $key_715f = { 22 30 [2] 06 3e [2] 2d 12 [2] 03 30 [2] 17 2b [2] 18 31 [2] 06 2c [2] 04 2d [2] 1f 2b [2] 03 2c [2] 1f 03 }

  condition:
    any of them
}