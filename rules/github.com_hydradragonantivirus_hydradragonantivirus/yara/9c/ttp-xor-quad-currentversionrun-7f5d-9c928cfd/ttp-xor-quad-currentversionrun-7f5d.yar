rule TTP_XOR_QUAD_CurrentVersionRun_7f5d {
  strings:
    $key_7f5d = { 2c 32 [2] 08 3c [2] 23 10 [2] 0d 32 [2] 19 29 [2] 16 33 [2] 08 2e [2] 0a 2f [2] 11 29 [2] 0d 2e [2] 11 01 }

  condition:
    any of them
}