rule TTP_XOR_QUAD_CurrentVersionRun_2503 {
  strings:
    $key_2503 = { 76 6c [2] 52 62 [2] 79 4e [2] 57 6c [2] 43 77 [2] 4c 6d [2] 52 70 [2] 50 71 [2] 4b 77 [2] 57 70 [2] 4b 5f }

  condition:
    any of them
}