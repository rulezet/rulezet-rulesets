rule TTP_XOR_QUAD_CurrentVersionRun_5d5d {
  strings:
    $key_5d5d = { 0e 32 [2] 2a 3c [2] 01 10 [2] 2f 32 [2] 3b 29 [2] 34 33 [2] 2a 2e [2] 28 2f [2] 33 29 [2] 2f 2e [2] 33 01 }

  condition:
    any of them
}