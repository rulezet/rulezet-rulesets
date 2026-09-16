rule TTP_XOR_QUAD_CurrentVersionRun_2823 {
  strings:
    $key_2823 = { 7b 4c [2] 5f 42 [2] 74 6e [2] 5a 4c [2] 4e 57 [2] 41 4d [2] 5f 50 [2] 5d 51 [2] 46 57 [2] 5a 50 [2] 46 7f }

  condition:
    any of them
}