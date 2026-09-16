rule TTP_XOR_QUAD_CurrentVersionRun_7503 {
  strings:
    $key_7503 = { 26 6c [2] 02 62 [2] 29 4e [2] 07 6c [2] 13 77 [2] 1c 6d [2] 02 70 [2] 00 71 [2] 1b 77 [2] 07 70 [2] 1b 5f }

  condition:
    any of them
}