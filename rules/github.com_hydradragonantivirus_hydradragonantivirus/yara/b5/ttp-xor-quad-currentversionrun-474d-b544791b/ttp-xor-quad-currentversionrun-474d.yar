rule TTP_XOR_QUAD_CurrentVersionRun_474d {
  strings:
    $key_474d = { 14 22 [2] 30 2c [2] 1b 00 [2] 35 22 [2] 21 39 [2] 2e 23 [2] 30 3e [2] 32 3f [2] 29 39 [2] 35 3e [2] 29 11 }

  condition:
    any of them
}