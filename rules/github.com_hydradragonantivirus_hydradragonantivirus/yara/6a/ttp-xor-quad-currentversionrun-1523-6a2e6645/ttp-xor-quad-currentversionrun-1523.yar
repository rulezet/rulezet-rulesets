rule TTP_XOR_QUAD_CurrentVersionRun_1523 {
  strings:
    $key_1523 = { 46 4c [2] 62 42 [2] 49 6e [2] 67 4c [2] 73 57 [2] 7c 4d [2] 62 50 [2] 60 51 [2] 7b 57 [2] 67 50 [2] 7b 7f }

  condition:
    any of them
}