rule TTP_XOR_QUAD_CurrentVersionRun_6f5d {
  strings:
    $key_6f5d = { 3c 32 [2] 18 3c [2] 33 10 [2] 1d 32 [2] 09 29 [2] 06 33 [2] 18 2e [2] 1a 2f [2] 01 29 [2] 1d 2e [2] 01 01 }

  condition:
    any of them
}