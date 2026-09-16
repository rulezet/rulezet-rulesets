rule TTP_XOR_QUAD_CurrentVersionRun_5e7f {
  strings:
    $key_5e7f = { 0d 10 [2] 29 1e [2] 02 32 [2] 2c 10 [2] 38 0b [2] 37 11 [2] 29 0c [2] 2b 0d [2] 30 0b [2] 2c 0c [2] 30 23 }

  condition:
    any of them
}