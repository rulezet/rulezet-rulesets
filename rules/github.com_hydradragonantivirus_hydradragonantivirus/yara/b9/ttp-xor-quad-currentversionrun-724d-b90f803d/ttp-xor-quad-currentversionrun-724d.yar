rule TTP_XOR_QUAD_CurrentVersionRun_724d {
  strings:
    $key_724d = { 21 22 [2] 05 2c [2] 2e 00 [2] 00 22 [2] 14 39 [2] 1b 23 [2] 05 3e [2] 07 3f [2] 1c 39 [2] 00 3e [2] 1c 11 }

  condition:
    any of them
}