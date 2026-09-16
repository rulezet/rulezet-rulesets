rule TTP_XOR_QUAD_CurrentVersionRun_2f23 {
  strings:
    $key_2f23 = { 7c 4c [2] 58 42 [2] 73 6e [2] 5d 4c [2] 49 57 [2] 46 4d [2] 58 50 [2] 5a 51 [2] 41 57 [2] 5d 50 [2] 41 7f }

  condition:
    any of them
}