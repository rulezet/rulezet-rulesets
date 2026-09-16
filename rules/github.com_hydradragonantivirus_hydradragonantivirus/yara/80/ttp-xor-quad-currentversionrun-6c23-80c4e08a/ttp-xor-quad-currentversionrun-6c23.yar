rule TTP_XOR_QUAD_CurrentVersionRun_6c23 {
  strings:
    $key_6c23 = { 3f 4c [2] 1b 42 [2] 30 6e [2] 1e 4c [2] 0a 57 [2] 05 4d [2] 1b 50 [2] 19 51 [2] 02 57 [2] 1e 50 [2] 02 7f }

  condition:
    any of them
}