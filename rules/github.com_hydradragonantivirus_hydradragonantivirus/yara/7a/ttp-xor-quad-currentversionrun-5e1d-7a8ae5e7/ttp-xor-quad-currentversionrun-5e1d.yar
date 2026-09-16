rule TTP_XOR_QUAD_CurrentVersionRun_5e1d {
  strings:
    $key_5e1d = { 0d 72 [2] 29 7c [2] 02 50 [2] 2c 72 [2] 38 69 [2] 37 73 [2] 29 6e [2] 2b 6f [2] 30 69 [2] 2c 6e [2] 30 41 }

  condition:
    any of them
}