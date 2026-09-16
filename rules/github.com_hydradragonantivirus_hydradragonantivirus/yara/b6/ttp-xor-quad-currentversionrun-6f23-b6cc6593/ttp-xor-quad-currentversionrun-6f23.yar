rule TTP_XOR_QUAD_CurrentVersionRun_6f23 {
  strings:
    $key_6f23 = { 3c 4c [2] 18 42 [2] 33 6e [2] 1d 4c [2] 09 57 [2] 06 4d [2] 18 50 [2] 1a 51 [2] 01 57 [2] 1d 50 [2] 01 7f }

  condition:
    any of them
}