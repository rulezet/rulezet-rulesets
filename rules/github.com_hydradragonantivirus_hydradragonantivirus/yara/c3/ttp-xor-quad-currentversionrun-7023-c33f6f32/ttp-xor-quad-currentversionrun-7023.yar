rule TTP_XOR_QUAD_CurrentVersionRun_7023 {
  strings:
    $key_7023 = { 23 4c [2] 07 42 [2] 2c 6e [2] 02 4c [2] 16 57 [2] 19 4d [2] 07 50 [2] 05 51 [2] 1e 57 [2] 02 50 [2] 1e 7f }

  condition:
    any of them
}