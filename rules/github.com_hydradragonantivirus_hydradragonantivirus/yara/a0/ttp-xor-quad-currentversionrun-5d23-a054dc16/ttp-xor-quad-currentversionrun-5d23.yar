rule TTP_XOR_QUAD_CurrentVersionRun_5d23 {
  strings:
    $key_5d23 = { 0e 4c [2] 2a 42 [2] 01 6e [2] 2f 4c [2] 3b 57 [2] 34 4d [2] 2a 50 [2] 28 51 [2] 33 57 [2] 2f 50 [2] 33 7f }

  condition:
    any of them
}