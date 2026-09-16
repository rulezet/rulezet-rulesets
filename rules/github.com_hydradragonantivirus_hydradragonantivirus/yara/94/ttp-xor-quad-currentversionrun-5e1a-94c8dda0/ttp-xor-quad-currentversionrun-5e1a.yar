rule TTP_XOR_QUAD_CurrentVersionRun_5e1a {
  strings:
    $key_5e1a = { 0d 75 [2] 29 7b [2] 02 57 [2] 2c 75 [2] 38 6e [2] 37 74 [2] 29 69 [2] 2b 68 [2] 30 6e [2] 2c 69 [2] 30 46 }

  condition:
    any of them
}