rule TTP_XOR_QUAD_CurrentVersionRun_6703 {
  strings:
    $key_6703 = { 34 6c [2] 10 62 [2] 3b 4e [2] 15 6c [2] 01 77 [2] 0e 6d [2] 10 70 [2] 12 71 [2] 09 77 [2] 15 70 [2] 09 5f }

  condition:
    any of them
}