rule TTP_XOR_QUAD_CurrentVersionRun_5d5c {
  strings:
    $key_5d5c = { 0e 33 [2] 2a 3d [2] 01 11 [2] 2f 33 [2] 3b 28 [2] 34 32 [2] 2a 2f [2] 28 2e [2] 33 28 [2] 2f 2f [2] 33 00 }

  condition:
    any of them
}