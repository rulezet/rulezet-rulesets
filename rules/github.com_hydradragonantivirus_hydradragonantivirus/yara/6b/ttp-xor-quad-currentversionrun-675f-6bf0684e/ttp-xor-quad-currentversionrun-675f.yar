rule TTP_XOR_QUAD_CurrentVersionRun_675f {
  strings:
    $key_675f = { 34 30 [2] 10 3e [2] 3b 12 [2] 15 30 [2] 01 2b [2] 0e 31 [2] 10 2c [2] 12 2d [2] 09 2b [2] 15 2c [2] 09 03 }

  condition:
    any of them
}