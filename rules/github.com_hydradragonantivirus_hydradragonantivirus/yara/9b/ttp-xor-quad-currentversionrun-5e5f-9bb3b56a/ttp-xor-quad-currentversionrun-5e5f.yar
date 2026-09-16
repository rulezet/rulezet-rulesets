rule TTP_XOR_QUAD_CurrentVersionRun_5e5f {
  strings:
    $key_5e5f = { 0d 30 [2] 29 3e [2] 02 12 [2] 2c 30 [2] 38 2b [2] 37 31 [2] 29 2c [2] 2b 2d [2] 30 2b [2] 2c 2c [2] 30 03 }

  condition:
    any of them
}