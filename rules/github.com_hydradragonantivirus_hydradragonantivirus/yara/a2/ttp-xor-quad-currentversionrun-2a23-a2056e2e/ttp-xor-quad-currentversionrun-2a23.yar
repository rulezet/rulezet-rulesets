rule TTP_XOR_QUAD_CurrentVersionRun_2a23 {
  strings:
    $key_2a23 = { 79 4c [2] 5d 42 [2] 76 6e [2] 58 4c [2] 4c 57 [2] 43 4d [2] 5d 50 [2] 5f 51 [2] 44 57 [2] 58 50 [2] 44 7f }

  condition:
    any of them
}