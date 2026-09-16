rule TTP_XOR_QUAD_CurrentVersionRun_5c4c {
  strings:
    $key_5c4c = { 0f 23 [2] 2b 2d [2] 00 01 [2] 2e 23 [2] 3a 38 [2] 35 22 [2] 2b 3f [2] 29 3e [2] 32 38 [2] 2e 3f [2] 32 10 }

  condition:
    any of them
}