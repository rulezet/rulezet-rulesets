rule TTP_XOR_QUAD_CurrentVersionRun_455f {
  strings:
    $key_455f = { 16 30 [2] 32 3e [2] 19 12 [2] 37 30 [2] 23 2b [2] 2c 31 [2] 32 2c [2] 30 2d [2] 2b 2b [2] 37 2c [2] 2b 03 }

  condition:
    any of them
}