rule TTP_XOR_QUAD_CurrentVersionRun_3123 {
  strings:
    $key_3123 = { 62 4c [2] 46 42 [2] 6d 6e [2] 43 4c [2] 57 57 [2] 58 4d [2] 46 50 [2] 44 51 [2] 5f 57 [2] 43 50 [2] 5f 7f }

  condition:
    any of them
}