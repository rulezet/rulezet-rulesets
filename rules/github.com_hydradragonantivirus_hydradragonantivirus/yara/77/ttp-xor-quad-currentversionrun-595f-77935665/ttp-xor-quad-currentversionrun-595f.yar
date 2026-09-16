rule TTP_XOR_QUAD_CurrentVersionRun_595f {
  strings:
    $key_595f = { 0a 30 [2] 2e 3e [2] 05 12 [2] 2b 30 [2] 3f 2b [2] 30 31 [2] 2e 2c [2] 2c 2d [2] 37 2b [2] 2b 2c [2] 37 03 }

  condition:
    any of them
}