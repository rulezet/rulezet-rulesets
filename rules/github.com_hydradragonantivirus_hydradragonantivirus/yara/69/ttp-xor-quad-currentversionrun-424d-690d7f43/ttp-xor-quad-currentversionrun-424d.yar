rule TTP_XOR_QUAD_CurrentVersionRun_424d {
  strings:
    $key_424d = { 11 22 [2] 35 2c [2] 1e 00 [2] 30 22 [2] 24 39 [2] 2b 23 [2] 35 3e [2] 37 3f [2] 2c 39 [2] 30 3e [2] 2c 11 }

  condition:
    any of them
}