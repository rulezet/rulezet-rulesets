rule TTP_XOR_QUAD_CurrentVersionRun_422e {
  strings:
    $key_422e = { 11 41 [2] 35 4f [2] 1e 63 [2] 30 41 [2] 24 5a [2] 2b 40 [2] 35 5d [2] 37 5c [2] 2c 5a [2] 30 5d [2] 2c 72 }

  condition:
    any of them
}