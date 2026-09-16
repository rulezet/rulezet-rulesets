rule TTP_XOR_QUAD_CurrentVersionRun_422f {
  strings:
    $key_422f = { 11 40 [2] 35 4e [2] 1e 62 [2] 30 40 [2] 24 5b [2] 2b 41 [2] 35 5c [2] 37 5d [2] 2c 5b [2] 30 5c [2] 2c 73 }

  condition:
    any of them
}