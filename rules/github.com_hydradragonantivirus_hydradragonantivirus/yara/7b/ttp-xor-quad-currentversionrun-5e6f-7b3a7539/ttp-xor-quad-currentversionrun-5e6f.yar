rule TTP_XOR_QUAD_CurrentVersionRun_5e6f {
  strings:
    $key_5e6f = { 0d 00 [2] 29 0e [2] 02 22 [2] 2c 00 [2] 38 1b [2] 37 01 [2] 29 1c [2] 2b 1d [2] 30 1b [2] 2c 1c [2] 30 33 }

  condition:
    any of them
}