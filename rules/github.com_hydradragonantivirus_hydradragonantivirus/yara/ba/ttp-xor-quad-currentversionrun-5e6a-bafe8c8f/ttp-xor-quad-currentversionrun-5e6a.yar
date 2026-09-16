rule TTP_XOR_QUAD_CurrentVersionRun_5e6a {
  strings:
    $key_5e6a = { 0d 05 [2] 29 0b [2] 02 27 [2] 2c 05 [2] 38 1e [2] 37 04 [2] 29 19 [2] 2b 18 [2] 30 1e [2] 2c 19 [2] 30 36 }

  condition:
    any of them
}