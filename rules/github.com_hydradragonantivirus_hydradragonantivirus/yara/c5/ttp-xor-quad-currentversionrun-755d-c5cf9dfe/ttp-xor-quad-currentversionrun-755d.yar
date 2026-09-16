rule TTP_XOR_QUAD_CurrentVersionRun_755d {
  strings:
    $key_755d = { 26 32 [2] 02 3c [2] 29 10 [2] 07 32 [2] 13 29 [2] 1c 33 [2] 02 2e [2] 00 2f [2] 1b 29 [2] 07 2e [2] 1b 01 }

  condition:
    any of them
}