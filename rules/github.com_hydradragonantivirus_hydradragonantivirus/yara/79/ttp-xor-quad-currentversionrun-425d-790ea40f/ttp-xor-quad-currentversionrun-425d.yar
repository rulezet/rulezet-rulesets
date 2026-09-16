rule TTP_XOR_QUAD_CurrentVersionRun_425d {
  strings:
    $key_425d = { 11 32 [2] 35 3c [2] 1e 10 [2] 30 32 [2] 24 29 [2] 2b 33 [2] 35 2e [2] 37 2f [2] 2c 29 [2] 30 2e [2] 2c 01 }

  condition:
    any of them
}