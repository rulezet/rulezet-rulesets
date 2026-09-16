rule TTP_XOR_QUAD_CurrentVersionRun_422c {
  strings:
    $key_422c = { 11 43 [2] 35 4d [2] 1e 61 [2] 30 43 [2] 24 58 [2] 2b 42 [2] 35 5f [2] 37 5e [2] 2c 58 [2] 30 5f [2] 2c 70 }

  condition:
    any of them
}