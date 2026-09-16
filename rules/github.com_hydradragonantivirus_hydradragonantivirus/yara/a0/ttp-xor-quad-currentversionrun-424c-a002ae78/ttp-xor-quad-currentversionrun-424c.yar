rule TTP_XOR_QUAD_CurrentVersionRun_424c {
  strings:
    $key_424c = { 11 23 [2] 35 2d [2] 1e 01 [2] 30 23 [2] 24 38 [2] 2b 22 [2] 35 3f [2] 37 3e [2] 2c 38 [2] 30 3f [2] 2c 10 }

  condition:
    any of them
}