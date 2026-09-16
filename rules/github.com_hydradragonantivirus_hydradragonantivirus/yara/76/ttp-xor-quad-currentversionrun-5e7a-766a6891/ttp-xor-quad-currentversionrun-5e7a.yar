rule TTP_XOR_QUAD_CurrentVersionRun_5e7a {
  strings:
    $key_5e7a = { 0d 15 [2] 29 1b [2] 02 37 [2] 2c 15 [2] 38 0e [2] 37 14 [2] 29 09 [2] 2b 08 [2] 30 0e [2] 2c 09 [2] 30 26 }

  condition:
    any of them
}