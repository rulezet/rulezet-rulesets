rule TTP_XOR_QUAD_CurrentVersionRun_5e50 {
  strings:
    $key_5e50 = { 0d 3f [2] 29 31 [2] 02 1d [2] 2c 3f [2] 38 24 [2] 37 3e [2] 29 23 [2] 2b 22 [2] 30 24 [2] 2c 23 [2] 30 0c }

  condition:
    any of them
}