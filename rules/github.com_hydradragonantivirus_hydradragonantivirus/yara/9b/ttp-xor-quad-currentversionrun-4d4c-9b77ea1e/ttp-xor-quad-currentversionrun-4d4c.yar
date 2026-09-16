rule TTP_XOR_QUAD_CurrentVersionRun_4d4c {
  strings:
    $key_4d4c = { 1e 23 [2] 3a 2d [2] 11 01 [2] 3f 23 [2] 2b 38 [2] 24 22 [2] 3a 3f [2] 38 3e [2] 23 38 [2] 3f 3f [2] 23 10 }

  condition:
    any of them
}