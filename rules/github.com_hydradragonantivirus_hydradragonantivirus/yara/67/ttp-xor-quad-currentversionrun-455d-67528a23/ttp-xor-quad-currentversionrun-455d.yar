rule TTP_XOR_QUAD_CurrentVersionRun_455d {
  strings:
    $key_455d = { 16 32 [2] 32 3c [2] 19 10 [2] 37 32 [2] 23 29 [2] 2c 33 [2] 32 2e [2] 30 2f [2] 2b 29 [2] 37 2e [2] 2b 01 }

  condition:
    any of them
}