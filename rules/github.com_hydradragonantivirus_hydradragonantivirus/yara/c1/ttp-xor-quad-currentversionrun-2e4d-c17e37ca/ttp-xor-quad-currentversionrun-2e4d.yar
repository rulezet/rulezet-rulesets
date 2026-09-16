rule TTP_XOR_QUAD_CurrentVersionRun_2e4d {
  strings:
    $key_2e4d = { 7d 22 [2] 59 2c [2] 72 00 [2] 5c 22 [2] 48 39 [2] 47 23 [2] 59 3e [2] 5b 3f [2] 40 39 [2] 5c 3e [2] 40 11 }

  condition:
    any of them
}