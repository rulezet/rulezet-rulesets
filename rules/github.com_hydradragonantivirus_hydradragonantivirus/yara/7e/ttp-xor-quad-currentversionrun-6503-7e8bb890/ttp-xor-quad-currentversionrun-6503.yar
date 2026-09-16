rule TTP_XOR_QUAD_CurrentVersionRun_6503 {
  strings:
    $key_6503 = { 36 6c [2] 12 62 [2] 39 4e [2] 17 6c [2] 03 77 [2] 0c 6d [2] 12 70 [2] 10 71 [2] 0b 77 [2] 17 70 [2] 0b 5f }

  condition:
    any of them
}