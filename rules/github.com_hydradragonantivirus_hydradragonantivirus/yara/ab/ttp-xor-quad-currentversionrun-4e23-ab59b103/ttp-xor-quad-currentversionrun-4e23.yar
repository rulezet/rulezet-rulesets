rule TTP_XOR_QUAD_CurrentVersionRun_4e23 {
  strings:
    $key_4e23 = { 1d 4c [2] 39 42 [2] 12 6e [2] 3c 4c [2] 28 57 [2] 27 4d [2] 39 50 [2] 3b 51 [2] 20 57 [2] 3c 50 [2] 20 7f }

  condition:
    any of them
}