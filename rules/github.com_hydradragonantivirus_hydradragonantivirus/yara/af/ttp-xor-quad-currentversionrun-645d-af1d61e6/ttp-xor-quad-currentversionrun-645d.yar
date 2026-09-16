rule TTP_XOR_QUAD_CurrentVersionRun_645d {
  strings:
    $key_645d = { 37 32 [2] 13 3c [2] 38 10 [2] 16 32 [2] 02 29 [2] 0d 33 [2] 13 2e [2] 11 2f [2] 0a 29 [2] 16 2e [2] 0a 01 }

  condition:
    any of them
}