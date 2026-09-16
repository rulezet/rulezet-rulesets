rule TTP_XOR_QUAD_CurrentVersionRun_4200 {
  strings:
    $key_4200 = { 11 6f [2] 35 61 [2] 1e 4d [2] 30 6f [2] 24 74 [2] 2b 6e [2] 35 73 [2] 37 72 [2] 2c 74 [2] 30 73 [2] 2c 5c }

  condition:
    any of them
}