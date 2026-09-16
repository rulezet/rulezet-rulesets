rule TTP_XOR_QUAD_CurrentVersionRun_2523 {
  strings:
    $key_2523 = { 76 4c [2] 52 42 [2] 79 6e [2] 57 4c [2] 43 57 [2] 4c 4d [2] 52 50 [2] 50 51 [2] 4b 57 [2] 57 50 [2] 4b 7f }

  condition:
    any of them
}