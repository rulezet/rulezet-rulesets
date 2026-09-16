rule TTP_XOR_QUAD_CurrentVersionRun_456f {
  strings:
    $key_456f = { 16 00 [2] 32 0e [2] 19 22 [2] 37 00 [2] 23 1b [2] 2c 01 [2] 32 1c [2] 30 1d [2] 2b 1b [2] 37 1c [2] 2b 33 }

  condition:
    any of them
}