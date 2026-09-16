rule TTP_XOR_QUAD_CurrentVersionRun_705f {
  strings:
    $key_705f = { 23 30 [2] 07 3e [2] 2c 12 [2] 02 30 [2] 16 2b [2] 19 31 [2] 07 2c [2] 05 2d [2] 1e 2b [2] 02 2c [2] 1e 03 }

  condition:
    any of them
}