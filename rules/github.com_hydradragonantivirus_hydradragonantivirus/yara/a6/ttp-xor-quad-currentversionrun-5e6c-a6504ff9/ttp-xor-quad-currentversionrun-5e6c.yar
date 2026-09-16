rule TTP_XOR_QUAD_CurrentVersionRun_5e6c {
  strings:
    $key_5e6c = { 0d 03 [2] 29 0d [2] 02 21 [2] 2c 03 [2] 38 18 [2] 37 02 [2] 29 1f [2] 2b 1e [2] 30 18 [2] 2c 1f [2] 30 30 }

  condition:
    any of them
}