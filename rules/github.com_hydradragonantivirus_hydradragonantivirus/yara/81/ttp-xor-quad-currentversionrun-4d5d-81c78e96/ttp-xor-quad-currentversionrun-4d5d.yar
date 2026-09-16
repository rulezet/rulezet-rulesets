rule TTP_XOR_QUAD_CurrentVersionRun_4d5d {
  strings:
    $key_4d5d = { 1e 32 [2] 3a 3c [2] 11 10 [2] 3f 32 [2] 2b 29 [2] 24 33 [2] 3a 2e [2] 38 2f [2] 23 29 [2] 3f 2e [2] 23 01 }

  condition:
    any of them
}