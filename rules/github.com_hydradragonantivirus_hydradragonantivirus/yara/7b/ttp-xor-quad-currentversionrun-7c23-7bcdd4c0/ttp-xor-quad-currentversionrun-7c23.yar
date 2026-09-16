rule TTP_XOR_QUAD_CurrentVersionRun_7c23 {
  strings:
    $key_7c23 = { 2f 4c [2] 0b 42 [2] 20 6e [2] 0e 4c [2] 1a 57 [2] 15 4d [2] 0b 50 [2] 09 51 [2] 12 57 [2] 0e 50 [2] 12 7f }

  condition:
    any of them
}