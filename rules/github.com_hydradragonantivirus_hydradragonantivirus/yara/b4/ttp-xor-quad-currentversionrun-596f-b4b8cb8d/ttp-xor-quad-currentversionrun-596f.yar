rule TTP_XOR_QUAD_CurrentVersionRun_596f {
  strings:
    $key_596f = { 0a 00 [2] 2e 0e [2] 05 22 [2] 2b 00 [2] 3f 1b [2] 30 01 [2] 2e 1c [2] 2c 1d [2] 37 1b [2] 2b 1c [2] 37 33 }

  condition:
    any of them
}