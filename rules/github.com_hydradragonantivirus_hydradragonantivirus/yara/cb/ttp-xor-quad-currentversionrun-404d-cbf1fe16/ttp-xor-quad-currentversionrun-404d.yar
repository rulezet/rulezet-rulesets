rule TTP_XOR_QUAD_CurrentVersionRun_404d {
  strings:
    $key_404d = { 13 22 [2] 37 2c [2] 1c 00 [2] 32 22 [2] 26 39 [2] 29 23 [2] 37 3e [2] 35 3f [2] 2e 39 [2] 32 3e [2] 2e 11 }

  condition:
    any of them
}