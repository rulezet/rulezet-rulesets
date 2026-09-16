rule TTP_XOR_QUAD_CurrentVersionRun_6c5f {
  strings:
    $key_6c5f = { 3f 30 [2] 1b 3e [2] 30 12 [2] 1e 30 [2] 0a 2b [2] 05 31 [2] 1b 2c [2] 19 2d [2] 02 2b [2] 1e 2c [2] 02 03 }

  condition:
    any of them
}