rule TTP_XOR_QUAD_CurrentVersionRun_e503 {
  strings:
    $key_e503 = { b6 6c [2] 92 62 [2] b9 4e [2] 97 6c [2] 83 77 [2] 8c 6d [2] 92 70 [2] 90 71 [2] 8b 77 [2] 97 70 [2] 8b 5f }

  condition:
    any of them
}