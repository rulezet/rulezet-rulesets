rule TTP_XOR_QUAD_CurrentVersionRun_6023 {
  strings:
    $key_6023 = { 33 4c [2] 17 42 [2] 3c 6e [2] 12 4c [2] 06 57 [2] 09 4d [2] 17 50 [2] 15 51 [2] 0e 57 [2] 12 50 [2] 0e 7f }

  condition:
    any of them
}