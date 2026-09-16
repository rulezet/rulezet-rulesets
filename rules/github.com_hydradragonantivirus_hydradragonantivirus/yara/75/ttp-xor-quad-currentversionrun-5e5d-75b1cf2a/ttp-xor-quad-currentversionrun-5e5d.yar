rule TTP_XOR_QUAD_CurrentVersionRun_5e5d {
  strings:
    $key_5e5d = { 0d 32 [2] 29 3c [2] 02 10 [2] 2c 32 [2] 38 29 [2] 37 33 [2] 29 2e [2] 2b 2f [2] 30 29 [2] 2c 2e [2] 30 01 }

  condition:
    any of them
}