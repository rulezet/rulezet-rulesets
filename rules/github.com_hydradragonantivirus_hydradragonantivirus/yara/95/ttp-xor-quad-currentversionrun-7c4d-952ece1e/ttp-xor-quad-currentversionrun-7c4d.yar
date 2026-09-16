rule TTP_XOR_QUAD_CurrentVersionRun_7c4d {
  strings:
    $key_7c4d = { 2f 22 [2] 0b 2c [2] 20 00 [2] 0e 22 [2] 1a 39 [2] 15 23 [2] 0b 3e [2] 09 3f [2] 12 39 [2] 0e 3e [2] 12 11 }

  condition:
    any of them
}