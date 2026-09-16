rule TTP_XOR_QUAD_CurrentVersionRun_585f {
  strings:
    $key_585f = { 0b 30 [2] 2f 3e [2] 04 12 [2] 2a 30 [2] 3e 2b [2] 31 31 [2] 2f 2c [2] 2d 2d [2] 36 2b [2] 2a 2c [2] 36 03 }

  condition:
    any of them
}