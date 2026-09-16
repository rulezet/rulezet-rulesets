rule TTP_XOR_QUAD_CurrentVersionRun_4d5c {
  strings:
    $key_4d5c = { 1e 33 [2] 3a 3d [2] 11 11 [2] 3f 33 [2] 2b 28 [2] 24 32 [2] 3a 2f [2] 38 2e [2] 23 28 [2] 3f 2f [2] 23 00 }

  condition:
    any of them
}