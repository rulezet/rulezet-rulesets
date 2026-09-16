rule TTP_XOR_QUAD_CurrentVersionRun_4d23 {
  strings:
    $key_4d23 = { 1e 4c [2] 3a 42 [2] 11 6e [2] 3f 4c [2] 2b 57 [2] 24 4d [2] 3a 50 [2] 38 51 [2] 23 57 [2] 3f 50 [2] 23 7f }

  condition:
    any of them
}